import pytest
from pydantic import ValidationError

from network_a.summary.summary_schema import (
    ALLOWED_FIELDS,
    AccessDecision,
    AuthStability,
    BehaviourLabel,
    NetworkBContext,
    PduSessionStability,
    PolicyEngineMetadata,
    SimulatedEnforcement,
    SummaryRequest,
    SummaryResponse,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)


def _make_summary(**overrides) -> UeBehaviouralSummary:
    defaults = {
        "auth_stability": AuthStability.HIGH,
        "pdu_session_stability": PduSessionStability.HIGH,
        "traffic_pattern": TrafficPattern.STABLE,
        "known_slice_usage": ["eMBB"],
        "recent_anomaly": False,
        "behaviour_label": BehaviourLabel.NORMAL,
    }
    defaults.update(overrides)
    return UeBehaviouralSummary(**defaults)


class TestUeBehaviouralSummary:
    def test_valid_summary(self):
        s = _make_summary()
        assert s.auth_stability == AuthStability.HIGH
        assert s.recent_anomaly is False

    def test_all_bad_summary(self):
        s = _make_summary(
            auth_stability=AuthStability.LOW,
            pdu_session_stability=PduSessionStability.LOW,
            traffic_pattern=TrafficPattern.VOLATILE,
            recent_anomaly=True,
            behaviour_label=BehaviourLabel.ANOMALOUS,
        )
        assert s.behaviour_label == BehaviourLabel.ANOMALOUS

    def test_invalid_auth_stability_rejected(self):
        with pytest.raises(ValidationError):
            _make_summary(auth_stability="invalid")

    def test_invalid_traffic_pattern_rejected(self):
        with pytest.raises(ValidationError):
            _make_summary(traffic_pattern="unknown")


class TestSummaryRequest:
    def test_valid_request(self):
        req = SummaryRequest(
            request_id="REQ-001",
            ue_pseudonym="UE_HASH_001",
            network_b_context=NetworkBContext(
                requested_slice="eMBB",
                requested_dnn="internet",
                requested_service="standard_data",
            ),
        )
        assert set(req.requested_fields) == ALLOWED_FIELDS

    def test_custom_fields(self):
        req = SummaryRequest(
            request_id="REQ-002",
            ue_pseudonym="UE_HASH_001",
            requested_fields=["auth_stability"],
            network_b_context=NetworkBContext(
                requested_slice="eMBB",
                requested_dnn="internet",
                requested_service="standard_data",
            ),
        )
        assert req.requested_fields == ["auth_stability"]


class TestTiers:
    def test_tier_ordering(self):
        from network_a.summary.summary_schema import TIER_ORDER

        assert TIER_ORDER[Tier.T0_REJECT] < TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]
        assert TIER_ORDER[Tier.T1_RESTRICTED_ACCESS] < TIER_ORDER[Tier.T2_MONITORED_ACCESS]
        assert TIER_ORDER[Tier.T2_MONITORED_ACCESS] < TIER_ORDER[Tier.T3_FULL_ACCESS]

    def test_tier_values(self):
        assert Tier.T3_FULL_ACCESS.value == "T3_FULL_ACCESS"
        assert Tier.T0_REJECT.value == "T0_REJECT"


class TestAccessDecision:
    def test_valid_decision(self):
        d = AccessDecision(
            request_id="REQ-001",
            ue_pseudonym="UE_HASH_001",
            final_tier=Tier.T3_FULL_ACCESS,
            risk_score=0.05,
            reason="All clear",
            policy_engine_metadata=PolicyEngineMetadata(
                deterministic_max_tier=Tier.T3_FULL_ACCESS.value,
            ),
            simulated_enforcement=SimulatedEnforcement(),
            decided_at="2026-05-05T12:00:00Z",
        )
        assert d.final_tier == Tier.T3_FULL_ACCESS

    def test_risk_score_bounds(self):
        with pytest.raises(ValidationError):
            AccessDecision(
                request_id="REQ-001",
                ue_pseudonym="UE_HASH_001",
                final_tier=Tier.T3_FULL_ACCESS,
                risk_score=1.5,
                reason="Bad",
                policy_engine_metadata=PolicyEngineMetadata(
                    deterministic_max_tier=Tier.T3_FULL_ACCESS.value,
                ),
                simulated_enforcement=SimulatedEnforcement(),
                decided_at="2026-05-05T12:00:00Z",
            )
