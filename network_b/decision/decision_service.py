from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone

import httpx

from network_a.summary.summary_schema import (
    AccessDecision,
    AccessRequest,
    NetworkBContext,
    PolicyEngineMetadata,
    SimulatedEnforcement,
    SummaryRequest,
    SummaryResponse,
    Tier,
)
from network_b.decision.decision_logger import log_decision
from network_b.policy.policy_engine import decide_auto
from network_b.rag.retriever import Retriever

logger = logging.getLogger(__name__)

NETWORK_A_URL = os.environ.get("NETWORK_A_URL", "http://localhost:8001")

# Lazy-initialized RAG retriever shared across access requests. Built once
# per process so the vector store + embeddings client are reused. ``None``
# means RAG is disabled or unavailable (empty KB, missing index, etc.).
_RETRIEVER: Retriever | None = None
_RETRIEVER_LOCK = threading.Lock()
_RETRIEVER_INITIALIZED = False


def get_retriever() -> Retriever | None:
    global _RETRIEVER, _RETRIEVER_INITIALIZED
    if _RETRIEVER_INITIALIZED:
        return _RETRIEVER
    with _RETRIEVER_LOCK:
        if _RETRIEVER_INITIALIZED:
            return _RETRIEVER
        try:
            _RETRIEVER = Retriever.from_disk()
        except Exception as exc:  # noqa: BLE001
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
    with _RETRIEVER_LOCK:
        _RETRIEVER = None
        _RETRIEVER_INITIALIZED = False

ENFORCEMENT_MAP = {
    Tier.T0_REJECT: SimulatedEnforcement(
        bandwidth_cap_mbps=0,
        monitoring_interval_sec=None,
        allowed_services=[],
    ),
    Tier.T1_RESTRICTED_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=10,
        monitoring_interval_sec=30,
        allowed_services=["standard_data"],
    ),
    Tier.T2_MONITORED_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=50,
        monitoring_interval_sec=60,
        allowed_services=["standard_data"],
    ),
    Tier.T3_FULL_ACCESS: SimulatedEnforcement(
        bandwidth_cap_mbps=None,
        monitoring_interval_sec=None,
        allowed_services=["standard_data", "voice", "video", "iot"],
    ),
}


async def fetch_summary(
    ue_pseudonym: str,
    request_id: str,
    access_req: AccessRequest,
) -> SummaryResponse | None:
    summary_req = SummaryRequest(
        request_id=request_id,
        ue_pseudonym=ue_pseudonym,
        network_b_context=NetworkBContext(
            requested_slice=access_req.requested_slice,
            requested_dnn=access_req.requested_dnn,
            requested_service=access_req.requested_service,
        ),
    )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{NETWORK_A_URL}/v1/summary/request",
                json=summary_req.model_dump(mode="json"),
            )
        if resp.status_code == 200:
            return SummaryResponse.model_validate(resp.json())
        return None
    except httpx.HTTPError:
        return None


async def handle_access_request(access_req: AccessRequest) -> AccessDecision:
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
