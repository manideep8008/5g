from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    TrafficPattern,
    UeBehaviouralSummary,
)

FIELD_RISK_MAP = {
    AuthStability.HIGH: 0.0,
    AuthStability.MEDIUM: 0.5,
    AuthStability.LOW: 1.0,
    PduSessionStability.HIGH: 0.0,
    PduSessionStability.MEDIUM: 0.5,
    PduSessionStability.LOW: 1.0,
    TrafficPattern.STABLE: 0.0,
    TrafficPattern.MODERATE: 0.5,
    TrafficPattern.VOLATILE: 1.0,
    BehaviourLabel.NORMAL: 0.0,
    BehaviourLabel.SUSPICIOUS: 0.5,
    BehaviourLabel.ANOMALOUS: 1.0,
}

DEFAULT_WEIGHTS = {
    "auth_stability": 0.25,
    "pdu_session_stability": 0.20,
    "traffic_pattern": 0.20,
    "recent_anomaly": 0.20,
    "behaviour_label": 0.15,
}


def compute_risk_score(summary: UeBehaviouralSummary) -> float:
    score = 0.0
    score += DEFAULT_WEIGHTS["auth_stability"] * FIELD_RISK_MAP[summary.auth_stability]
    score += DEFAULT_WEIGHTS["pdu_session_stability"] * FIELD_RISK_MAP[summary.pdu_session_stability]
    score += DEFAULT_WEIGHTS["traffic_pattern"] * FIELD_RISK_MAP[summary.traffic_pattern]
    score += DEFAULT_WEIGHTS["recent_anomaly"] * (1.0 if summary.recent_anomaly else 0.0)
    score += DEFAULT_WEIGHTS["behaviour_label"] * FIELD_RISK_MAP[summary.behaviour_label]
    return round(min(max(score, 0.0), 1.0), 4)
