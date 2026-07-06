"""Unit tests for the normative grounding rules (grammar.md, "Grounding rules").

These tests construct Evidence directly — no database — so each rule's
boundary behavior is pinned independently of the seed scenarios.
"""

from datetime import datetime, timedelta, timezone

import pytest

from network_a.summary.agents import grounding
from network_a.summary.agents.evidence import Evidence
from network_a.summary.summary_generator import UeProfile
from network_a.summary.timeline import TimelineBucket

NOW = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)


def make_profile(**overrides) -> UeProfile:
    base = dict(
        pseudonym="UE_HASH_TEST",
        session_count=8,
        total_auth_attempts=40,
        total_auth_failures=0,
        auth_failure_rate=0.0,
        total_pdu_attempts=24,
        total_pdu_failures=0,
        pdu_failure_rate=0.0,
        total_bytes_uplink=0,
        total_bytes_downlink=0,
        peak_throughput_kbps=100,
        total_spike_count=0,
        spike_rate=0.0,
        known_slices=["eMBB"],
        known_dnns=["oai"],
        has_active_risk_flags=False,
    )
    base.update(overrides)
    return UeProfile(**base)


def make_bucket(**overrides) -> TimelineBucket:
    base = dict(
        session_count=4,
        auth_attempts=20,
        auth_failures=0,
        pdu_attempts=12,
        pdu_failures=0,
        spike_count=0,
    )
    base.update(overrides)
    return TimelineBucket(**base)


def make_evidence(
    profile: UeProfile | None = None,
    older: TimelineBucket | None = None,
    recent: TimelineBucket | None = None,
    flags: list[dict] | None = None,
    session_starts: list[datetime] | None = None,
    now: datetime = NOW,
) -> Evidence:
    if session_starts is None:
        session_starts = [NOW - timedelta(hours=8 - i) for i in range(8)]
    return Evidence(
        profile=profile or make_profile(),
        older=older or make_bucket(),
        recent=recent or make_bucket(),
        flags=flags if flags is not None else [],
        session_starts=session_starts,
        now=now,
    )


def flag(hours_ago: float, cleared: bool = False) -> dict:
    return {
        "pseudonym": "UE_HASH_TEST",
        "flag_type": "auth_burst",
        "severity": "medium",
        "flagged_at": (NOW - timedelta(hours=hours_ago)).isoformat(),
        "cleared_at": (NOW - timedelta(hours=hours_ago - 1)).isoformat() if cleared else None,
    }


# ── trend ────────────────────────────────────────────────────────


def test_trend_increasing():
    ev = make_evidence(
        older=make_bucket(auth_failures=0),
        recent=make_bucket(auth_failures=8),
    )
    assert grounding.ground("trend", {"facet": "auth_failures"}, ev) == "increasing"


def test_trend_decreasing():
    ev = make_evidence(
        older=make_bucket(auth_failures=8),
        recent=make_bucket(auth_failures=0),
    )
    assert grounding.ground("trend", {"facet": "auth_failures"}, ev) == "decreasing"


def test_trend_flat_within_dead_band():
    ev = make_evidence(
        older=make_bucket(auth_failures=2),   # rate 0.10
        recent=make_bucket(auth_failures=3),  # rate 0.15 → delta exactly 0.05
    )
    assert grounding.ground("trend", {"facet": "auth_failures"}, ev) == "flat"


def test_trend_unavailable_when_older_half_empty():
    ev = make_evidence(
        older=make_bucket(session_count=0, auth_attempts=0),
        recent=make_bucket(auth_failures=2),
    )
    assert grounding.ground("trend", {"facet": "auth_failures"}, ev) is None


def test_trend_traffic_spikes_uses_spike_rate():
    ev = make_evidence(
        older=make_bucket(spike_count=4),
        recent=make_bucket(spike_count=0),
    )
    assert grounding.ground("trend", {"facet": "traffic_spikes"}, ev) == "decreasing"


def test_trend_pdu_failures():
    ev = make_evidence(
        older=make_bucket(pdu_failures=0),
        recent=make_bucket(pdu_failures=6),
    )
    assert grounding.ground("trend", {"facet": "pdu_failures"}, ev) == "increasing"


# ── flag_age ─────────────────────────────────────────────────────


def test_flag_age_none_without_flags():
    assert grounding.ground("flag_age", {}, make_evidence()) == "none"


def test_flag_age_recent():
    ev = make_evidence(flags=[flag(hours_ago=2)])
    assert grounding.ground("flag_age", {}, ev) == "recent"


def test_flag_age_old():
    ev = make_evidence(flags=[flag(hours_ago=10)])
    assert grounding.ground("flag_age", {}, ev) == "old"


def test_flag_age_ignores_flags_outside_window():
    ev = make_evidence(flags=[flag(hours_ago=25)])
    assert grounding.ground("flag_age", {}, ev) == "none"


# ── stability / traffic buckets ──────────────────────────────────


@pytest.mark.parametrize(
    "rate, expected",
    [(0.0, "high"), (0.1, "medium"), (0.5, "low")],
)
def test_auth_stability_buckets(rate, expected):
    ev = make_evidence(profile=make_profile(auth_failure_rate=rate))
    assert grounding.ground("auth_stability", {}, ev) == expected


def test_pdu_stability_buckets():
    ev = make_evidence(profile=make_profile(pdu_failure_rate=0.5))
    assert grounding.ground("pdu_stability", {}, ev) == "low"


@pytest.mark.parametrize(
    "rate, expected",
    [(0.05, "stable"), (0.2, "moderate"), (0.6, "volatile")],
)
def test_traffic_pattern_buckets(rate, expected):
    ev = make_evidence(profile=make_profile(spike_rate=rate))
    assert grounding.ground("traffic_pattern", {}, ev) == expected


# ── session_regularity ───────────────────────────────────────────


def test_regularity_unavailable_below_three_sessions():
    ev = make_evidence(session_starts=[NOW - timedelta(hours=2), NOW - timedelta(hours=1)])
    assert grounding.ground("session_regularity", {}, ev) is None


def test_regular_when_gaps_are_even():
    starts = [NOW - timedelta(hours=8 - i) for i in range(8)]
    assert grounding.ground("session_regularity", {}, make_evidence(session_starts=starts)) == "regular"


def test_irregular_when_gaps_vary_widely():
    offsets_hours = [0, 1, 11, 12, 32]
    starts = [NOW - timedelta(hours=40) + timedelta(hours=h) for h in offsets_hours]
    assert grounding.ground("session_regularity", {}, make_evidence(session_starts=starts)) == "irregular"


# ── resource_novelty ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "kind, value, expected",
    [
        ("slice", "eMBB", "known"),
        ("slice", "URLLC", "novel"),
        ("dnn", "oai", "known"),
        ("dnn", "internet", "novel"),
    ],
)
def test_resource_novelty(kind, value, expected):
    ev = make_evidence()
    assert grounding.ground("resource_novelty", {"kind": kind, "value": value}, ev) == expected


# ── anomaly_status ───────────────────────────────────────────────


def test_anomaly_none_without_flags():
    assert grounding.ground("anomaly_status", {}, make_evidence()) == "none"


def test_anomaly_active_when_flag_open_and_recent_half_dirty():
    ev = make_evidence(
        flags=[flag(hours_ago=2)],
        recent=make_bucket(auth_failures=4, spike_count=2),
    )
    assert grounding.ground("anomaly_status", {}, ev) == "active"


def test_anomaly_resolved_when_recent_half_clean():
    ev = make_evidence(
        flags=[flag(hours_ago=9)],
        older=make_bucket(auth_failures=8, spike_count=8),
        recent=make_bucket(auth_failures=0, spike_count=0),
    )
    assert grounding.ground("anomaly_status", {}, ev) == "resolved"


def test_anomaly_resolved_when_all_flags_cleared():
    ev = make_evidence(
        flags=[flag(hours_ago=9, cleared=True)],
        recent=make_bucket(auth_failures=2),
    )
    assert grounding.ground("anomaly_status", {}, ev) == "resolved"


def test_anomaly_none_when_flags_outside_window():
    ev = make_evidence(flags=[flag(hours_ago=30)])
    assert grounding.ground("anomaly_status", {}, ev) == "none"
