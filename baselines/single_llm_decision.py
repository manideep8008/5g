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
    AccessDecision,
    AccessRequest,
    PolicyEngineMetadata,
    SimulatedEnforcement,
    Tier,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import LlmConfig, call_llm, load_llm_config
from network_b.policy.risk_score import compute_risk_score

logger = logging.getLogger(__name__)

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
