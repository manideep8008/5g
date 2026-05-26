"""Tests for risk_flag_generator — bucketization thresholds."""

import pytest

from network_a.summary.summary_generator import (
    UeProfile,
    BucketThresholds,
    classify_auth_stability,
    classify_behaviour_label,
    classify_pdu_stability,
    classify_traffic_pattern,
    compute_overall_risk,
    generate_behavioural_summary,
)
from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    TrafficPattern,
)

THRESHOLDS = BucketThresholds(
    auth_high_max=0.05,
    auth_medium_max=0.20,
    pdu_high_max=0.05,
    pdu_medium_max=0.20,
    traffic_stable_max=0.10,
    traffic_moderate_max=0.30,
    behaviour_normal_max=0.20,
    behaviour_suspicious_max=0.50,
)


def _make_profile(**overrides) -> UeProfile:
    defaults = dict(
        pseudonym="UE_HASH_TEST",
        session_count=10,
        total_auth_attempts=100,
        total_auth_failures=2,
        auth_failure_rate=0.02,
        total_pdu_attempts=50,
        total_pdu_failures=1,
        pdu_failure_rate=0.02,
        total_bytes_uplink=50000,
        total_bytes_downlink=200000,
        peak_throughput_kbps=500,
        total_spike_count=0,
        spike_rate=0.0,
        known_slices=["eMBB"],
        known_dnns=["internet"],
        has_active_risk_flags=False,
    )
    defaults.update(overrides)
    return UeProfile(**defaults)


class TestAuthStabilityClassification:
    def test_high(self):
        assert classify_auth_stability(0.0, THRESHOLDS) == AuthStability.HIGH
        assert classify_auth_stability(0.05, THRESHOLDS) == AuthStability.HIGH

    def test_medium(self):
        assert classify_auth_stability(0.06, THRESHOLDS) == AuthStability.MEDIUM
        assert classify_auth_stability(0.20, THRESHOLDS) == AuthStability.MEDIUM

    def test_low(self):
        assert classify_auth_stability(0.21, THRESHOLDS) == AuthStability.LOW
        assert classify_auth_stability(1.0, THRESHOLDS) == AuthStability.LOW


class TestPduStabilityClassification:
    def test_high(self):
        assert classify_pdu_stability(0.0, THRESHOLDS) == PduSessionStability.HIGH

    def test_medium(self):
        assert classify_pdu_stability(0.10, THRESHOLDS) == PduSessionStability.MEDIUM

    def test_low(self):
        assert classify_pdu_stability(0.25, THRESHOLDS) == PduSessionStability.LOW


class TestTrafficPatternClassification:
    def test_stable(self):
        assert classify_traffic_pattern(0.0, THRESHOLDS) == TrafficPattern.STABLE
        assert classify_traffic_pattern(0.10, THRESHOLDS) == TrafficPattern.STABLE

    def test_moderate(self):
        assert classify_traffic_pattern(0.15, THRESHOLDS) == TrafficPattern.MODERATE
        assert classify_traffic_pattern(0.30, THRESHOLDS) == TrafficPattern.MODERATE

    def test_volatile(self):
        assert classify_traffic_pattern(0.31, THRESHOLDS) == TrafficPattern.VOLATILE
        assert classify_traffic_pattern(1.0, THRESHOLDS) == TrafficPattern.VOLATILE


class TestBehaviourLabelClassification:
    def test_normal(self):
        assert classify_behaviour_label(0.0, THRESHOLDS) == BehaviourLabel.NORMAL
        assert classify_behaviour_label(0.20, THRESHOLDS) == BehaviourLabel.NORMAL

    def test_suspicious(self):
        assert classify_behaviour_label(0.25, THRESHOLDS) == BehaviourLabel.SUSPICIOUS
        assert classify_behaviour_label(0.50, THRESHOLDS) == BehaviourLabel.SUSPICIOUS

    def test_anomalous(self):
        assert classify_behaviour_label(0.51, THRESHOLDS) == BehaviourLabel.ANOMALOUS
        assert classify_behaviour_label(1.0, THRESHOLDS) == BehaviourLabel.ANOMALOUS


class TestOverallRisk:
    def test_clean_profile(self):
        profile = _make_profile(auth_failure_rate=0.0, pdu_failure_rate=0.0, spike_rate=0.0)
        risk = compute_overall_risk(profile)
        assert risk == 0.0

    def test_all_bad(self):
        profile = _make_profile(
            auth_failure_rate=1.0,
            pdu_failure_rate=1.0,
            spike_rate=1.0,
            has_active_risk_flags=True,
        )
        risk = compute_overall_risk(profile)
        assert risk == 1.0

    def test_partial_risk(self):
        profile = _make_profile(auth_failure_rate=0.5, pdu_failure_rate=0.0, spike_rate=0.0)
        risk = compute_overall_risk(profile)
        assert risk == pytest.approx(0.15, abs=0.01)

    def test_risk_flags_contribution(self):
        profile_no_flags = _make_profile(has_active_risk_flags=False)
        profile_with_flags = _make_profile(has_active_risk_flags=True)
        assert compute_overall_risk(profile_with_flags) > compute_overall_risk(profile_no_flags)


class TestGenerateBehaviouralSummary:
    def test_normal_ue(self):
        profile = _make_profile()
        summary = generate_behavioural_summary(profile, THRESHOLDS)
        assert summary.auth_stability == AuthStability.HIGH
        assert summary.pdu_session_stability == PduSessionStability.HIGH
        assert summary.traffic_pattern == TrafficPattern.STABLE
        assert summary.recent_anomaly is False
        assert summary.behaviour_label == BehaviourLabel.NORMAL
        assert summary.known_slice_usage == ["eMBB"]

    def test_suspicious_ue(self):
        profile = _make_profile(
            auth_failure_rate=0.15,
            pdu_failure_rate=0.10,
            spike_rate=0.25,
            has_active_risk_flags=True,
        )
        summary = generate_behavioural_summary(profile, THRESHOLDS)
        assert summary.auth_stability == AuthStability.MEDIUM
        assert summary.pdu_session_stability == PduSessionStability.MEDIUM
        assert summary.traffic_pattern == TrafficPattern.MODERATE
        assert summary.recent_anomaly is True
        assert summary.behaviour_label == BehaviourLabel.SUSPICIOUS

    def test_anomalous_ue(self):
        profile = _make_profile(
            auth_failure_rate=0.50,
            pdu_failure_rate=0.50,
            spike_rate=0.80,
            has_active_risk_flags=True,
        )
        summary = generate_behavioural_summary(profile, THRESHOLDS)
        assert summary.auth_stability == AuthStability.LOW
        assert summary.pdu_session_stability == PduSessionStability.LOW
        assert summary.traffic_pattern == TrafficPattern.VOLATILE
        assert summary.behaviour_label == BehaviourLabel.ANOMALOUS

    def test_default_slice_when_empty(self):
        profile = _make_profile(known_slices=[])
        summary = generate_behavioural_summary(profile, THRESHOLDS)
        assert summary.known_slice_usage == ["eMBB"]

    def test_multiple_slices(self):
        profile = _make_profile(known_slices=["eMBB", "URLLC"])
        summary = generate_behavioural_summary(profile, THRESHOLDS)
        assert summary.known_slice_usage == ["eMBB", "URLLC"]
