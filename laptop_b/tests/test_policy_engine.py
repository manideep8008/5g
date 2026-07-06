from network_b.contract.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.policy.policy_engine import decide, compute_risk_score, apply_safety_floor, risk_to_max_tier


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


class TestRiskScore:
    def test_all_good_is_zero(self):
        s = _make_summary()
        assert compute_risk_score(s) == 0.0

    def test_all_bad_is_one(self):
        s = _make_summary(
            auth_stability=AuthStability.LOW,
            pdu_session_stability=PduSessionStability.LOW,
            traffic_pattern=TrafficPattern.VOLATILE,
            recent_anomaly=True,
            behaviour_label=BehaviourLabel.ANOMALOUS,
        )
        assert compute_risk_score(s) == 1.0

    def test_medium_risk_in_range(self):
        s = _make_summary(
            auth_stability=AuthStability.MEDIUM,
            traffic_pattern=TrafficPattern.MODERATE,
        )
        score = compute_risk_score(s)
        assert 0.0 < score < 1.0

    def test_anomaly_flag_adds_risk(self):
        s_no_anomaly = _make_summary()
        s_anomaly = _make_summary(recent_anomaly=True)
        assert compute_risk_score(s_anomaly) > compute_risk_score(s_no_anomaly)


class TestTierMapper:
    def test_low_risk_gives_full_access(self):
        assert risk_to_max_tier(0.10) == Tier.T3_FULL_ACCESS

    def test_mid_risk_gives_monitored(self):
        assert risk_to_max_tier(0.35) == Tier.T2_MONITORED_ACCESS

    def test_high_risk_gives_restricted(self):
        assert risk_to_max_tier(0.65) == Tier.T1_RESTRICTED_ACCESS

    def test_very_high_risk_gives_reject(self):
        assert risk_to_max_tier(0.90) == Tier.T0_REJECT

    def test_boundary_020_is_full_access(self):
        assert risk_to_max_tier(0.20) == Tier.T3_FULL_ACCESS

    def test_boundary_050_is_monitored(self):
        assert risk_to_max_tier(0.50) == Tier.T2_MONITORED_ACCESS

    def test_boundary_080_is_restricted(self):
        assert risk_to_max_tier(0.80) == Tier.T1_RESTRICTED_ACCESS


class TestSafetyFloor:
    def test_no_clip_for_clean_summary(self):
        s = _make_summary()
        tier, clipped, reason = apply_safety_floor(Tier.T3_FULL_ACCESS, s)
        assert tier == Tier.T3_FULL_ACCESS
        assert clipped is False
        assert reason is None

    def test_anomaly_clips_to_t2(self):
        s = _make_summary(recent_anomaly=True)
        tier, clipped, reason = apply_safety_floor(Tier.T3_FULL_ACCESS, s)
        assert tier == Tier.T2_MONITORED_ACCESS
        assert clipped is True

    def test_low_auth_clips_to_t1(self):
        s = _make_summary(auth_stability=AuthStability.LOW)
        tier, clipped, reason = apply_safety_floor(Tier.T3_FULL_ACCESS, s)
        assert tier == Tier.T1_RESTRICTED_ACCESS
        assert clipped is True

    def test_anomalous_behaviour_clips_to_t1(self):
        s = _make_summary(behaviour_label=BehaviourLabel.ANOMALOUS)
        tier, clipped, reason = apply_safety_floor(Tier.T3_FULL_ACCESS, s)
        assert tier == Tier.T1_RESTRICTED_ACCESS
        assert clipped is True

    def test_already_restricted_no_clip(self):
        s = _make_summary(recent_anomaly=True)
        tier, clipped, reason = apply_safety_floor(Tier.T1_RESTRICTED_ACCESS, s)
        assert tier == Tier.T1_RESTRICTED_ACCESS
        assert clipped is False


class TestPolicyEngineDecide:
    def test_clean_ue_gets_full_access(self):
        s = _make_summary()
        result = decide(s)
        assert result.tier == Tier.T3_FULL_ACCESS
        assert result.risk_score == 0.0
        assert result.metadata.safety_floor_clipped is False

    def test_anomaly_ue_gets_clipped(self):
        s = _make_summary(recent_anomaly=True)
        result = decide(s)
        assert result.tier == Tier.T2_MONITORED_ACCESS
        assert result.metadata.safety_floor_clipped is True

    def test_all_bad_ue_gets_rejected(self):
        s = _make_summary(
            auth_stability=AuthStability.LOW,
            pdu_session_stability=PduSessionStability.LOW,
            traffic_pattern=TrafficPattern.VOLATILE,
            recent_anomaly=True,
            behaviour_label=BehaviourLabel.ANOMALOUS,
        )
        result = decide(s)
        assert result.tier in (Tier.T0_REJECT, Tier.T1_RESTRICTED_ACCESS)
        assert result.risk_score >= 0.80
