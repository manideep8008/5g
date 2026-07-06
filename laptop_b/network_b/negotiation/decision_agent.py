"""The decision agent: Network B's ask/decide loop over one negotiation.

Action space is deliberately tiny — ask the next best question or decide a
tier. The agent stops when the risk interval pins a single tier (unknowns
provably cannot change the decision), when the budget or question limits
bite, or when nothing informative is left to ask; every early stop decides
against the conservative ``risk_max`` bound. The deterministic floor in
``belief.apply_negotiated_floor`` is applied last and can only lower a tier.

One accountable locus: this loop produces exactly one decide() per session,
and the sealed transcript on Network A records how it got there.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from network_b.contract.negotiation_schemas import (
    CloseRequest,
    NegotiationContext,
    QueryRequest,
    SessionOpenRequest,
)
from network_b.contract.summary_schema import TIER_ORDER, Tier
from network_b.negotiation.belief import (
    Beliefs,
    SUPPORTED_GRAMMAR_VERSION,
    apply_negotiated_floor,
    candidate_questions,
    risk_bounds,
    tier_for,
)

logger = logging.getLogger(__name__)

MAX_QUESTIONS = 10
FAST_PATH_MIN_CONFIDENCE = 0.8


@dataclass(frozen=True)
class NegotiationOutcome:
    final_tier: Tier
    risk_score: float
    reason: str
    stop_reason: str
    questions_asked: int
    budget_spent: int
    transcript_hash: str | None
    deterministic_max_tier: Tier
    floor_clipped: bool
    floor_reason: str | None
    facts: dict[str, str] = field(default_factory=dict)


def _parse_tier(value: str) -> Tier | None:
    try:
        return Tier(value)
    except ValueError:
        return None


def _more_restrictive(a: Tier, b: Tier) -> Tier:
    return a if TIER_ORDER[a] <= TIER_ORDER[b] else b


async def negotiate(
    client,
    ue_pseudonym: str,
    context: NegotiationContext,
    request_id: str,
) -> NegotiationOutcome | None:
    """Run one negotiation. Returns None when the protocol fails (channel
    down, bad signatures, unsupported grammar) — the caller falls back to
    the existing one-shot path, which itself fails closed."""
    opened = await client.open(SessionOpenRequest(
        request_id=request_id,
        ue_pseudonym=ue_pseudonym,
        requester_id="network_b",
        context=context,
    ))
    if opened is None:
        return None
    if opened.grammar_version != SUPPORTED_GRAMMAR_VERSION:
        logger.warning(
            "unsupported grammar version %d from Network A — aborting negotiation",
            opened.grammar_version,
        )
        return None

    attestation = opened.minimal_attestation
    beliefs = Beliefs(
        behaviour_label=attestation.behaviour_label,
        recent_anomaly=attestation.recent_anomaly,
    )
    budget_remaining = opened.budget_remaining
    questions_asked = 0
    budget_spent = 0

    # Fast path: an attested-normal, unflagged UE at high confidence is the
    # easy majority — decide from the free attestation alone.
    if (
        attestation.behaviour_label == "normal"
        and not attestation.recent_anomaly
        and attestation.confidence >= FAST_PATH_MIN_CONFIDENCE
    ):
        risk_min, _ = risk_bounds(beliefs)
        recommended = _parse_tier(attestation.recommendation) or tier_for(risk_min)
        tier = _more_restrictive(recommended, tier_for(risk_min))
        stop_reason = "fast_path"
        risk_score = risk_min
    else:
        stop_reason = None
        while True:
            risk_min, risk_max = risk_bounds(beliefs)
            if tier_for(risk_min) == tier_for(risk_max):
                stop_reason = "tier_stable"
                break
            if questions_asked >= MAX_QUESTIONS:
                stop_reason = "max_questions"
                break
            affordable = candidate_questions(beliefs, budget_remaining)
            if not affordable:
                informative = candidate_questions(beliefs, budget_remaining=None)
                stop_reason = (
                    "budget_exhausted" if informative else "no_informative_questions"
                )
                break

            question = affordable[0]
            resp = await client.query(QueryRequest(
                session_id=opened.session_id,
                predicate=question.predicate,
                args=question.args,
            ))
            if resp is None:
                logger.warning(
                    "negotiation channel failed mid-session for %s", ue_pseudonym
                )
                return None

            questions_asked += 1
            budget_remaining = resp.budget_remaining
            if resp.status == "answered":
                beliefs.facts[question.facet_key] = resp.answer
                budget_spent += resp.cost or 0
            elif resp.status == "unavailable":
                beliefs.unresolvable.add(question.facet_key)
            elif resp.status == "refused":
                stop_reason = "budget_exhausted"
                break
            else:  # "rejected" — off-grammar means a bug on our side
                logger.error(
                    "Network A rejected %s as off-grammar — agent/grammar drift",
                    question.predicate,
                )
                beliefs.unresolvable.add(question.facet_key)

        _, risk_max = risk_bounds(beliefs)
        tier = tier_for(risk_max)
        risk_score = risk_max

    deterministic_max_tier = tier
    final_tier, clipped, floor_reason = apply_negotiated_floor(tier, beliefs)

    reason = (
        f"Negotiated decision ({stop_reason}): risk {risk_score:.2f} → "
        f"{deterministic_max_tier.value} after {questions_asked} question(s), "
        f"{budget_spent} budget point(s)"
    )
    if clipped:
        reason += f"; floor applied: {floor_reason}"

    closed = await client.close(CloseRequest(
        session_id=opened.session_id, final_tier=final_tier.value
    ))
    if closed is None:
        logger.warning(
            "failed to close negotiation session for %s — transcript hash unknown",
            ue_pseudonym,
        )

    return NegotiationOutcome(
        final_tier=final_tier,
        risk_score=risk_score,
        reason=reason,
        stop_reason=stop_reason,
        questions_asked=questions_asked,
        budget_spent=budget_spent,
        transcript_hash=closed.transcript_hash if closed else None,
        deterministic_max_tier=deterministic_max_tier,
        floor_clipped=clipped,
        floor_reason=floor_reason,
        facts=dict(beliefs.facts),
    )
