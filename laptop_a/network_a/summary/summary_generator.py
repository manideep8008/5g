from dataclasses import dataclass
from datetime import datetime, timezone
import functools
from pathlib import Path

import yaml

from network_a import db
from network_a.summary.summary_schema import (
    ALLOWED_FIELDS,
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    SummaryRequest,
    SummaryResponse,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_a_config.yaml"


@dataclass(frozen=True)
class UeProfile:
    pseudonym: str
    session_count: int
    total_auth_attempts: int
    total_auth_failures: int
    auth_failure_rate: float
    total_pdu_attempts: int
    total_pdu_failures: int
    pdu_failure_rate: float
    total_bytes_uplink: int
    total_bytes_downlink: int
    peak_throughput_kbps: int
    total_spike_count: int
    spike_rate: float
    known_slices: list[str]
    known_dnns: list[str]
    has_active_risk_flags: bool


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



async def build_profile(pseudonym: str, window_sec: int = 86400) -> UeProfile | None:
    #get the sessions for the UE pseudonym
    sessions = await db.get_sessions_for_ue(pseudonym, limit=200)
    if not sessions:
        return None

    total_auth_attempts = 0
    total_auth_failures = 0
    total_pdu_attempts = 0
    total_pdu_failures = 0
    total_bytes_uplink = 0
    total_bytes_downlink = 0
    peak_throughput = 0
    total_spike_count = 0
    slices: set[str] = set()
    dnns: set[str] = set()

    #aggregate the metrics from the sessions
    # sessions is a list of dicts, so 's' is one of those dicts on each iteration
    for s in sessions:
        #this is looking for "s" (a session dict) that we're iterating over
        #and getting the values for the keys 'auth_attempts', 'auth_failures', etc.
        #if the key is not found, it returns 0
        total_auth_attempts += s.get("auth_attempts", 0)
        total_auth_failures += s.get("auth_failures", 0)
        total_pdu_attempts += s.get("pdu_attempts", 0)
        total_pdu_failures += s.get("pdu_failures", 0)
        total_bytes_uplink += s.get("bytes_uplink", 0)
        total_bytes_downlink += s.get("bytes_downlink", 0)
        #s is a session dict. so this is looking for 'tp' (peak_throughput_kbps) and if it's not found, it returns 0
        tp = s.get("peak_throughput_kbps") or 0
        #then it checks if tp is greater than the current peak_throughput
        if tp > peak_throughput:
            peak_throughput = tp
        
        #this adds the spike_count from the current session to the total_spike_count
        total_spike_count += s.get("spike_count", 0)
        #this gets the requested_slice from the current session and adds it to the set of slices
        sl = s.get("requested_slice")
        if sl:
            slices.add(sl)
        #this gets the requested_dnn from the current session and adds it to the set of dnns
        dnn = s.get("requested_dnn")
        if dnn:
            dnns.add(dnn)

    #calculate the failure rates
    #if total_auth_attempts is greater than 0 and if so, it calculates the auth_failure_rate, otherwise it returns 0.0
    auth_failure_rate = (
        total_auth_failures / total_auth_attempts
        if total_auth_attempts > 0
        else 0.0
    )
    #this checks if total_pdu_attempts is greater than 0 and if so, it calculates the pdu_failure_rate, otherwise it returns 0.0
    pdu_failure_rate = (
        total_pdu_failures / total_pdu_attempts
        if total_pdu_attempts > 0
        else 0.0
    )
    #this is getting the number of sessions for the UE pseudonym
    session_count = len(sessions)

    #this is calculating the spike rate
    spike_rate = total_spike_count / session_count if session_count > 0 else 0.0

    #this is getting the active risk flags for the UE pseudonym
    risk_flags = await db.get_active_risk_flags(pseudonym)

    #this is checking if there are any active risk flags
    has_active_risk_flags = len(risk_flags) > 0

    #this is returning the UE profile with all the aggregated metrics
    return UeProfile(
        pseudonym=pseudonym,
        session_count=session_count,
        total_auth_attempts=total_auth_attempts,
        total_auth_failures=total_auth_failures,
        auth_failure_rate=round(auth_failure_rate, 4),
        total_pdu_attempts=total_pdu_attempts,
        total_pdu_failures=total_pdu_failures,
        pdu_failure_rate=round(pdu_failure_rate, 4),
        total_bytes_uplink=total_bytes_uplink,
        total_bytes_downlink=total_bytes_downlink,
        peak_throughput_kbps=peak_throughput,
        total_spike_count=total_spike_count,
        spike_rate=round(spike_rate, 4),
        known_slices=sorted(slices),
        known_dnns=sorted(dnns),
        has_active_risk_flags=has_active_risk_flags,
    )



#this is getting the thresholds from the config file
@functools.lru_cache()
def get_thresholds(config_path: Path | None = None) -> BucketThresholds:
    #setting the path to the config file
    path = config_path or _CONFIG_PATH
    #opening the config file
    with open(path) as f:
        #loading the config file
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

#this is classifying the auth stability based on the failure rate and the thresholds
def classify_auth_stability(failure_rate: float, t: BucketThresholds) -> AuthStability:
    #if the failure rate is less than or equal to the high threshold, it returns high
    if failure_rate <= t.auth_high_max:
        return AuthStability.HIGH
    #if the failure rate is less than or equal to the medium threshold, it returns medium
    if failure_rate <= t.auth_medium_max:
        return AuthStability.MEDIUM
    return AuthStability.LOW

#this is classifying the pdu stability based on the failure rate and the thresholds
def classify_pdu_stability(failure_rate: float, t: BucketThresholds) -> PduSessionStability:
    #if the failure rate is less than or equal to the high threshold, it returns high
    if failure_rate <= t.pdu_high_max:
        return PduSessionStability.HIGH
    #if the failure rate is less than or equal to the medium threshold, it returns medium
    if failure_rate <= t.pdu_medium_max:
        return PduSessionStability.MEDIUM
    return PduSessionStability.LOW

#this is classifying the traffic pattern based on the spike rate and the thresholds
def classify_traffic_pattern(spike_rate: float, t: BucketThresholds) -> TrafficPattern:
    #if the spike rate is less than or equal to the stable threshold, it returns stable
    if spike_rate <= t.traffic_stable_max:
        return TrafficPattern.STABLE
    #if the spike rate is less than or equal to the moderate threshold, it returns moderate
    if spike_rate <= t.traffic_moderate_max:
        return TrafficPattern.MODERATE
    return TrafficPattern.VOLATILE

#this is computing the overall risk
def compute_overall_risk(profile: UeProfile) -> float:
    #initializing the risk
    risk = 0.0
    #this is adding the auth failure rate to the risk (30% of the overall risk)
    risk += profile.auth_failure_rate * 0.30
    #this is adding the pdu failure rate to the risk (25% of the overall risk)
    risk += profile.pdu_failure_rate * 0.25
    #this is adding the spike rate to the risk (25% of the overall risk)
    risk += min(profile.spike_rate, 1.0) * 0.25
    #this is adding the active risk flags to the risk (20% of the overall risk)
    risk += (1.0 if profile.has_active_risk_flags else 0.0) * 0.20
    #this is returning the overall risk rounded to 4 decimal places
    return round(min(risk, 1.0), 4)

#this is classifying the behaviour label based on the overall risk and the thresholds   
def classify_behaviour_label(overall_risk: float, t: BucketThresholds) -> BehaviourLabel:
    #if the overall risk is less than or equal to the normal threshold, it returns normal
    if overall_risk <= t.behaviour_normal_max:
        return BehaviourLabel.NORMAL
    #if the overall risk is less than or equal to the suspicious threshold, it returns suspicious
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

_DEFAULT_WINDOW_SEC = 86400

_TIER_FROM_RISK = [
    (0.20, Tier.T3_FULL_ACCESS),
    (0.50, Tier.T2_MONITORED_ACCESS),
    (0.80, Tier.T1_RESTRICTED_ACCESS),
]


def recommend_tier(overall_risk: float) -> Tier:
    for threshold, tier in _TIER_FROM_RISK:
        if overall_risk <= threshold:
            return tier
    return Tier.T0_REJECT


def compute_confidence(profile: UeProfile, overall_risk: float) -> float:
    """Confidence in the classification, discounted when session data is sparse
    (full confidence only from 10 sessions up)."""
    data_sufficiency = min(profile.session_count / 10.0, 1.0)
    return round((1.0 - overall_risk) * data_sufficiency, 4)


async def generate_summary(
    request: SummaryRequest,
    window_sec: int = _DEFAULT_WINDOW_SEC,
) -> SummaryResponse | None:

    #check if the requested fields are allowed
    for field in request.requested_fields:
        if field not in ALLOWED_FIELDS:
            raise ValueError(f"Requested field '{field}' is not in the allowlist")

    #look up the identity in the Memory Store or postgres db.
    identity = await db.get_identity(request.ue_pseudonym)
    if identity is None:
        return None


    profile = await build_profile(request.ue_pseudonym, window_sec=window_sec)
    if profile is None:
        return None

    thresholds = get_thresholds()
    summary = generate_behavioural_summary(profile, thresholds)
    overall_risk = compute_overall_risk(profile)
    recommendation = recommend_tier(overall_risk)
    confidence = compute_confidence(profile, overall_risk)

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
