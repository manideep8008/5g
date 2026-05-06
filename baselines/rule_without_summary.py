"""
Baseline: Rules-only decision WITHOUT behavioural summary from Network A.

This baseline only has access to the AccessRequest fields (requested slice,
DNN, service). It cannot see any UE history. It applies conservative heuristics
based solely on what the UE is asking for.

Used in evaluation to show that the summary from Network A adds value.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from network_a.summary.summary_schema import (
    AccessDecision,
    AccessRequest,
    PolicyEngineMetadata,
    SimulatedEnforcement,
    Tier,
)

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

SLICE_RISK = {
    "eMBB": 0.1,
    "URLLC": 0.3,
    "mMTC": 0.2,
}

SERVICE_RISK = {
    "standard_data": 0.0,
    "voice": 0.1,
    "video": 0.15,
    "iot": 0.2,
    "emergency": 0.0,
}


def _risk_to_tier(risk: float) -> Tier:
    if risk <= 0.20:
        return Tier.T3_FULL_ACCESS
    if risk <= 0.50:
        return Tier.T2_MONITORED_ACCESS
    if risk <= 0.80:
        return Tier.T1_RESTRICTED_ACCESS
    return Tier.T0_REJECT


def decide_without_summary(access_req: AccessRequest) -> AccessDecision:
    slice_risk = SLICE_RISK.get(access_req.requested_slice, 0.4)
    service_risk = SERVICE_RISK.get(access_req.requested_service, 0.3)
    base_uncertainty = 0.35

    risk = round(base_uncertainty + slice_risk * 0.3 + service_risk * 0.3, 4)
    risk = min(risk, 1.0)

    tier = _risk_to_tier(risk)
    reason = (
        f"No summary available. Risk estimated from request context only: "
        f"slice={access_req.requested_slice} (+{slice_risk:.2f}), "
        f"service={access_req.requested_service} (+{service_risk:.2f}), "
        f"base_uncertainty=0.35"
    )

    return AccessDecision(
        request_id=access_req.request_id,
        ue_pseudonym=access_req.ue_pseudonym,
        final_tier=tier,
        risk_score=risk,
        reason=reason,
        policy_engine_metadata=PolicyEngineMetadata(
            llm_model_id="baseline_rule_without_summary",
            llm_temperature=0.0,
            llm_proposed_tier=None,
            safety_floor_clipped=False,
            safety_floor_reason=None,
            deterministic_max_tier=tier.value,
        ),
        simulated_enforcement=ENFORCEMENT_MAP[tier],
        decided_at=datetime.now(timezone.utc),
    )
