"""Network B Access Decision Service.

Coordinates requests from clients by requesting behavioural summaries from
Network A over HTTP, invoking the policy engine, grounding decisions using the
RAG retriever, and logging audit outcomes.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx

from network_b.contract import request_signer as rs
from network_b.contract.negotiation_schemas import NegotiationContext
from network_b.contract.summary_schema import (
    ENFORCEMENT_MAP,
    AccessDecision,
    AccessRequest,
    NetworkBContext,
    PolicyEngineMetadata,
    SummaryRequest,
    SummaryResponse,
    Tier,
)
from network_b.decision.decision_logger import log_decision
from network_b.negotiation.decision_agent import negotiate
from network_b.negotiation.session_client import SessionClient
from network_b.policy.policy_engine import decide_auto
from network_b.rag.retriever import Retriever

logger = logging.getLogger(__name__)

NETWORK_A_URL = os.environ.get("NETWORK_A_URL", "http://localhost:8001")
_SUMMARY_PATH = "/v1/summary/request"

# Replay cache for Network A's response signatures.
_RESPONSE_NONCES = rs.NonceCache()

_RETRIEVER: Retriever | None = None
_RETRIEVER_INITIALIZED = False


def get_retriever() -> Retriever | None:
    """Lazily load the RAG retriever instance once per process."""
    global _RETRIEVER, _RETRIEVER_INITIALIZED
    if not _RETRIEVER_INITIALIZED:
        try:
            _RETRIEVER = Retriever.from_disk()
        except Exception as exc:
            logger.warning("Failed to initialize RAG retriever: %s", exc)
            _RETRIEVER = None
        _RETRIEVER_INITIALIZED = True

        if _RETRIEVER is None:
            logger.info("RAG retriever not active — running without evidence grounding")
        else:
            logger.info("RAG retriever ready with %d indexed documents", _RETRIEVER.store.size)

    return _RETRIEVER


def reset_retriever_for_tests() -> None:
    """Clear the cached retriever; used by tests that swap the index."""
    global _RETRIEVER, _RETRIEVER_INITIALIZED
    _RETRIEVER = None
    _RETRIEVER_INITIALIZED = False


async def fetch_summary(
    ue_pseudonym: str,
    request_id: str,
    access_req: AccessRequest,
    client: httpx.AsyncClient | None = None,
) -> SummaryResponse | None:
    """Fetch a behavioural summary for ``ue_pseudonym`` from Network A.

    The outbound request is HMAC-signed, and Network A's response signature is
    verified before the body is trusted. When ``REQUIRE_SIGNED_REQUESTS`` is on
    (the default), a missing/invalid response signature fails closed: this
    returns None, and the caller drops the UE to T1.
    """
    summary_req = SummaryRequest(
        request_id=request_id,
        ue_pseudonym=ue_pseudonym,
        network_b_context=NetworkBContext(
            requested_slice=access_req.requested_slice,
            requested_dnn=access_req.requested_dnn,
            requested_service=access_req.requested_service,
        ),
    )

    body = rs.canonical_body(summary_req.model_dump(mode="json"))
    sig_headers = rs.sign("POST", _SUMMARY_PATH, body)
    headers = {**sig_headers, "content-type": "application/json"}

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=10.0)
    try:
        resp = await client.post(
            f"{NETWORK_A_URL}{_SUMMARY_PATH}", content=body, headers=headers
        )
        if resp.status_code != 200:
            return None

        if rs.signing_required():
            try:
                rs.verify(
                    "POST",
                    _SUMMARY_PATH,
                    resp.content,
                    resp.headers,
                    nonce_cache=_RESPONSE_NONCES,
                )
            except rs.SignatureError as exc:
                logger.warning(
                    "Rejecting Network A summary for %s — bad response signature: %s",
                    ue_pseudonym, exc,
                )
                return None

        return SummaryResponse.model_validate(resp.json())
    except httpx.HTTPError:
        return None
    finally:
        if owns_client:
            await client.aclose()


def negotiation_enabled() -> bool:
    """Feature flag for the negotiated attestation path (default off)."""
    return os.environ.get("NEGOTIATION_ENABLED", "false").strip().lower() in {
        "1", "true", "yes",
    }


async def negotiate_decision(
    access_req: AccessRequest,
    client: SessionClient | None = None,
) -> AccessDecision | None:
    """Decide via the negotiated attestation protocol.

    Returns None when the negotiation could not run (Network A unreachable,
    bad signatures, unsupported grammar) — the caller falls back to the
    one-shot path, which itself fails closed to T1.
    """
    outcome = await negotiate(
        client or SessionClient(),
        ue_pseudonym=access_req.ue_pseudonym,
        context=NegotiationContext(
            requested_slice=access_req.requested_slice,
            requested_dnn=access_req.requested_dnn,
            requested_service=access_req.requested_service,
        ),
        request_id=access_req.request_id,
    )
    if outcome is None:
        return None

    return AccessDecision(
        request_id=access_req.request_id,
        ue_pseudonym=access_req.ue_pseudonym,
        final_tier=outcome.final_tier,
        risk_score=outcome.risk_score,
        reason=outcome.reason,
        policy_engine_metadata=PolicyEngineMetadata(
            llm_model_id="rules_only",
            deterministic_max_tier=outcome.deterministic_max_tier.value,
            safety_floor_clipped=outcome.floor_clipped,
            safety_floor_reason=outcome.floor_reason,
            negotiated=True,
            negotiation_transcript_hash=outcome.transcript_hash,
            negotiation_budget_spent=outcome.budget_spent,
        ),
        simulated_enforcement=ENFORCEMENT_MAP[outcome.final_tier],
        decided_at=datetime.now(timezone.utc),
    )


async def handle_access_request(access_req: AccessRequest) -> AccessDecision:
    """Evaluate access request and return authorization tier decision."""
    if negotiation_enabled():
        negotiated = await negotiate_decision(access_req)
        if negotiated is not None:
            log_decision(negotiated)
            return negotiated
        logger.warning(
            "negotiation unavailable for %s — falling back to one-shot summary path",
            access_req.ue_pseudonym,
        )

    summary_resp = await fetch_summary(
        access_req.ue_pseudonym,
        access_req.request_id,
        access_req,
    )

    if summary_resp is None:
        decision = AccessDecision(
            request_id=access_req.request_id,
            ue_pseudonym=access_req.ue_pseudonym,
            final_tier=Tier.T1_RESTRICTED_ACCESS,
            risk_score=0.75,
            reason="No summary available from Network A — defaulting to restricted access",
            policy_engine_metadata=PolicyEngineMetadata(
                llm_model_id="rules_only",
                deterministic_max_tier=Tier.T1_RESTRICTED_ACCESS.value,
            ),
            simulated_enforcement=ENFORCEMENT_MAP[Tier.T1_RESTRICTED_ACCESS],
            decided_at=datetime.now(timezone.utc),
        )
    else:
        policy_result = await decide_auto(
            summary_resp.summary,
            requested_slice=access_req.requested_slice,
            requested_service=access_req.requested_service,
            retriever=get_retriever(),
        )
        decision = AccessDecision(
            request_id=access_req.request_id,
            ue_pseudonym=access_req.ue_pseudonym,
            final_tier=policy_result.tier,
            risk_score=policy_result.risk_score,
            reason=policy_result.reason,
            policy_engine_metadata=policy_result.metadata,
            simulated_enforcement=ENFORCEMENT_MAP[policy_result.tier],
            decided_at=datetime.now(timezone.utc),
            summary=summary_resp.summary,
            evidence_bundle=policy_result.evidence,
        )

    log_decision(decision)
    return decision
