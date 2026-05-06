from __future__ import annotations

from dataclasses import dataclass

from network_a import db


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


async def build_profile(pseudonym: str, window_sec: int = 86400) -> UeProfile | None:
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

    for s in sessions:
        total_auth_attempts += s.get("auth_attempts", 0)
        total_auth_failures += s.get("auth_failures", 0)
        total_pdu_attempts += s.get("pdu_attempts", 0)
        total_pdu_failures += s.get("pdu_failures", 0)
        total_bytes_uplink += s.get("bytes_uplink", 0)
        total_bytes_downlink += s.get("bytes_downlink", 0)
        tp = s.get("peak_throughput_kbps") or 0
        if tp > peak_throughput:
            peak_throughput = tp
        total_spike_count += s.get("spike_count", 0)
        sl = s.get("requested_slice")
        if sl:
            slices.add(sl)
        dnn = s.get("requested_dnn")
        if dnn:
            dnns.add(dnn)

    auth_failure_rate = (
        total_auth_failures / total_auth_attempts
        if total_auth_attempts > 0
        else 0.0
    )
    pdu_failure_rate = (
        total_pdu_failures / total_pdu_attempts
        if total_pdu_attempts > 0
        else 0.0
    )
    session_count = len(sessions)
    spike_rate = total_spike_count / session_count if session_count > 0 else 0.0

    risk_flags = await db.get_active_risk_flags(pseudonym)
    has_active_risk_flags = len(risk_flags) > 0

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
