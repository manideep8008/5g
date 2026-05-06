from __future__ import annotations

from datetime import datetime, timezone

from network_a import db
from network_a.summary.profile_builder import build_profile
from network_a.summary.risk_flag_generator import (
    compute_overall_risk,
    generate_behavioural_summary,
    get_thresholds,
)
from network_a.summary.summary_schema import (
    ALLOWED_FIELDS,
    SummaryRequest,
    SummaryResponse,
    Tier,
)

_DEFAULT_WINDOW_SEC = 86400

_TIER_FROM_RISK = [
    (0.20, Tier.T3_FULL_ACCESS),
    (0.50, Tier.T2_MONITORED_ACCESS),
    (0.80, Tier.T1_RESTRICTED_ACCESS),
]


def _recommend_tier(overall_risk: float) -> Tier:
    for threshold, tier in _TIER_FROM_RISK:
        if overall_risk <= threshold:
            return tier
    return Tier.T0_REJECT


async def generate_summary(
    request: SummaryRequest,
    window_sec: int = _DEFAULT_WINDOW_SEC,
) -> SummaryResponse | None:
    for field in request.requested_fields:
        if field not in ALLOWED_FIELDS:
            raise ValueError(f"Requested field '{field}' is not in the allowlist")

    identity = await db.get_identity(request.ue_pseudonym)
    if identity is None:
        return None

    profile = await build_profile(request.ue_pseudonym, window_sec=window_sec)
    if profile is None:
        return None

    thresholds = get_thresholds()
    summary = generate_behavioural_summary(profile, thresholds)
    overall_risk = compute_overall_risk(profile)
    recommendation = _recommend_tier(overall_risk)

    confidence = round(1.0 - overall_risk, 4)

    response = SummaryResponse(
        request_id=request.request_id,
        ue_pseudonym=request.ue_pseudonym,
        summary=summary,
        network_a_recommendation=recommendation.value,
        confidence=confidence,
        issued_at=datetime.now(timezone.utc),
        summary_window_sec=window_sec,
    )

    await db.log_summary_disclosure(
        request_id=request.request_id,
        pseudonym=request.ue_pseudonym,
        network_b_id=request.network_b_context.requested_service,
        summary_payload=response.summary.model_dump(),
        requested_fields=request.requested_fields,
    )

    return response
