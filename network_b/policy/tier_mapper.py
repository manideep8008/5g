from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    Tier,
    TIER_ORDER,
    UeBehaviouralSummary,
)


def risk_to_max_tier(risk_score: float) -> Tier:
    if risk_score <= 0.20:
        return Tier.T3_FULL_ACCESS
    if risk_score <= 0.50:
        return Tier.T2_MONITORED_ACCESS
    if risk_score <= 0.80:
        return Tier.T1_RESTRICTED_ACCESS
    return Tier.T0_REJECT


def apply_safety_floor(
    proposed_tier: Tier,
    summary: UeBehaviouralSummary,
) -> tuple[Tier, bool, str | None]:
    floor_tier = proposed_tier
    reason = None

    if summary.recent_anomaly and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T2_MONITORED_ACCESS]:
        floor_tier = Tier.T2_MONITORED_ACCESS
        reason = "recent_anomaly=true forced clip to T2"

    if summary.auth_stability == AuthStability.LOW and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor_tier = Tier.T1_RESTRICTED_ACCESS
        reason = "auth_stability=low forced clip to T1"

    if summary.behaviour_label == BehaviourLabel.ANOMALOUS and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor_tier = Tier.T1_RESTRICTED_ACCESS
        reason = "behaviour_label=anomalous forced clip to T1"

    clipped = floor_tier != proposed_tier
    return floor_tier, clipped, reason if clipped else None
