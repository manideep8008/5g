"""
Baseline: LLM-only decision WITHOUT safety floor.

This baseline sends the UE summary + access request to the LLM and accepts
whatever tier it proposes — no deterministic clipping. Used in evaluation to
show that the safety floor is necessary (LLM can be tricked by prompt injection).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from network_a.summary.summary_schema import (
    ENFORCEMENT_MAP,
    AccessDecision,
    AccessRequest,
    PolicyEngineMetadata,
    SimulatedEnforcement,
    Tier,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import LlmConfig, call_llm, load_llm_config
from network_b.policy.policy_engine import compute_risk_score

logger = logging.getLogger(__name__)




async def decide_llm_only(
    summary: UeBehaviouralSummary,
    access_req: AccessRequest,
    llm_config: LlmConfig | None = None,
) -> AccessDecision:
    cfg = llm_config or load_llm_config()
    risk = compute_risk_score(summary)

    proposal = await call_llm(
        summary,
        config=cfg,
        requested_slice=access_req.requested_slice,
        requested_service=access_req.requested_service,
    )

    if proposal is None:
        logger.warning("LLM unavailable in single_llm baseline, defaulting to T2")
        tier = Tier.T2_MONITORED_ACCESS
        reason = "LLM unavailable — conservative default"
    else:
        tier = proposal.proposed_tier
        reason = f"LLM decided {tier.value} (no safety floor): {proposal.reasoning}"

    return AccessDecision(
        request_id=access_req.request_id,
        ue_pseudonym=access_req.ue_pseudonym,
        final_tier=tier,
        risk_score=risk,
        reason=reason,
        policy_engine_metadata=PolicyEngineMetadata(
            llm_model_id=cfg.model,
            llm_temperature=cfg.temperature,
            llm_proposed_tier=tier.value,
            safety_floor_clipped=False,
            safety_floor_reason=None,
            deterministic_max_tier=tier.value,
        ),
        simulated_enforcement=ENFORCEMENT_MAP[tier],
        decided_at=datetime.now(timezone.utc),
    )
