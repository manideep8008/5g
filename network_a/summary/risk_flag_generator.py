from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from network_a.summary.profile_builder import UeProfile
from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    TrafficPattern,
    UeBehaviouralSummary,
)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_a_config.yaml"


@dataclass(frozen=True)
class BucketThresholds:
    auth_high_max: float
    auth_medium_max: float
    pdu_high_max: float
    pdu_medium_max: float
    traffic_stable_max: float
    traffic_moderate_max: float
    behaviour_normal_max: float
    behaviour_suspicious_max: float


def load_thresholds(config_path: Path | None = None) -> BucketThresholds:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f)

    b = cfg["bucketization"]
    return BucketThresholds(
        auth_high_max=b["auth_stability"]["high"]["max_failure_rate"],
        auth_medium_max=b["auth_stability"]["medium"]["max_failure_rate"],
        pdu_high_max=b["pdu_session_stability"]["high"]["max_failure_rate"],
        pdu_medium_max=b["pdu_session_stability"]["medium"]["max_failure_rate"],
        traffic_stable_max=b["traffic_pattern"]["stable"]["max_spike_rate"],
        traffic_moderate_max=b["traffic_pattern"]["moderate"]["max_spike_rate"],
        behaviour_normal_max=b["behaviour_label"]["normal"]["max_overall_risk"],
        behaviour_suspicious_max=b["behaviour_label"]["suspicious"]["max_overall_risk"],
    )


_cached_thresholds: BucketThresholds | None = None


def get_thresholds(config_path: Path | None = None) -> BucketThresholds:
    global _cached_thresholds
    if _cached_thresholds is None:
        _cached_thresholds = load_thresholds(config_path)
    return _cached_thresholds


def classify_auth_stability(failure_rate: float, t: BucketThresholds) -> AuthStability:
    if failure_rate <= t.auth_high_max:
        return AuthStability.HIGH
    if failure_rate <= t.auth_medium_max:
        return AuthStability.MEDIUM
    return AuthStability.LOW


def classify_pdu_stability(failure_rate: float, t: BucketThresholds) -> PduSessionStability:
    if failure_rate <= t.pdu_high_max:
        return PduSessionStability.HIGH
    if failure_rate <= t.pdu_medium_max:
        return PduSessionStability.MEDIUM
    return PduSessionStability.LOW


def classify_traffic_pattern(spike_rate: float, t: BucketThresholds) -> TrafficPattern:
    if spike_rate <= t.traffic_stable_max:
        return TrafficPattern.STABLE
    if spike_rate <= t.traffic_moderate_max:
        return TrafficPattern.MODERATE
    return TrafficPattern.VOLATILE


def compute_overall_risk(profile: UeProfile) -> float:
    risk = 0.0
    risk += profile.auth_failure_rate * 0.30
    risk += profile.pdu_failure_rate * 0.25
    risk += min(profile.spike_rate, 1.0) * 0.25
    risk += (1.0 if profile.has_active_risk_flags else 0.0) * 0.20
    return round(min(risk, 1.0), 4)


def classify_behaviour_label(overall_risk: float, t: BucketThresholds) -> BehaviourLabel:
    if overall_risk <= t.behaviour_normal_max:
        return BehaviourLabel.NORMAL
    if overall_risk <= t.behaviour_suspicious_max:
        return BehaviourLabel.SUSPICIOUS
    return BehaviourLabel.ANOMALOUS


def generate_behavioural_summary(
    profile: UeProfile,
    thresholds: BucketThresholds | None = None,
) -> UeBehaviouralSummary:
    t = thresholds or get_thresholds()

    auth_stability = classify_auth_stability(profile.auth_failure_rate, t)
    pdu_stability = classify_pdu_stability(profile.pdu_failure_rate, t)
    traffic_pattern = classify_traffic_pattern(profile.spike_rate, t)
    overall_risk = compute_overall_risk(profile)
    behaviour_label = classify_behaviour_label(overall_risk, t)

    return UeBehaviouralSummary(
        auth_stability=auth_stability,
        pdu_session_stability=pdu_stability,
        traffic_pattern=traffic_pattern,
        known_slice_usage=profile.known_slices if profile.known_slices else ["eMBB"],
        recent_anomaly=profile.has_active_risk_flags,
        behaviour_label=behaviour_label,
    )
