"""Normative grounding rules — the executable form of grammar.md.

One pure function per predicate, computing the entailed answer from an
Evidence bundle. Returns None when the evidence cannot support any answer
(the protocol's ``unavailable``). These functions are both the v1 responder
implementations and the verifier's reference: an answer that disagrees with
its grounding rule never leaves Network A.

Changing a rule here is a grammar change — update docs/design/grammar.md
and bump the grammar version with it.
"""

from __future__ import annotations

import statistics
from datetime import timedelta

from network_a.summary.agents.evidence import Evidence, as_datetime
from network_a.summary.summary_generator import (
    classify_auth_stability,
    classify_pdu_stability,
    classify_traffic_pattern,
    get_thresholds,
)
from network_a.summary.timeline import TimelineBucket

# Tunables documented in grammar.md; changing them is a grammar change.
TREND_DEAD_BAND = 0.05
RECENT_FLAG_MAX_AGE = timedelta(hours=6)
REGULARITY_MIN_SESSIONS = 3
REGULARITY_CV_MAX = 0.5


def _facet_rate(bucket: TimelineBucket, facet: str) -> float | None:
    rates = {
        "auth_failures": bucket.auth_failure_rate,
        "pdu_failures": bucket.pdu_failure_rate,
        "traffic_spikes": bucket.spike_rate,
    }
    return rates[facet]


def _trend(args: dict, ev: Evidence) -> str | None:
    older = _facet_rate(ev.older, args["facet"])
    recent = _facet_rate(ev.recent, args["facet"])
    if older is None or recent is None:
        return None
    delta = recent - older
    if abs(delta) <= TREND_DEAD_BAND:
        return "flat"
    return "increasing" if delta > 0 else "decreasing"


def _flags_in_window(ev: Evidence) -> list[dict]:
    cutoff = ev.now - timedelta(seconds=ev.window_sec)
    return [
        f for f in ev.flags
        if (ts := as_datetime(f.get("flagged_at"))) is not None and ts >= cutoff
    ]


def _flag_age(args: dict, ev: Evidence) -> str:
    flags = _flags_in_window(ev)
    if not flags:
        return "none"
    newest = max(as_datetime(f["flagged_at"]) for f in flags)
    return "recent" if ev.now - newest <= RECENT_FLAG_MAX_AGE else "old"


def _auth_stability(args: dict, ev: Evidence) -> str:
    return classify_auth_stability(ev.profile.auth_failure_rate, get_thresholds()).value


def _pdu_stability(args: dict, ev: Evidence) -> str:
    return classify_pdu_stability(ev.profile.pdu_failure_rate, get_thresholds()).value


def _traffic_pattern(args: dict, ev: Evidence) -> str:
    return classify_traffic_pattern(ev.profile.spike_rate, get_thresholds()).value


def _session_regularity(args: dict, ev: Evidence) -> str | None:
    if len(ev.session_starts) < REGULARITY_MIN_SESSIONS:
        return None
    gaps = [
        (b - a).total_seconds()
        for a, b in zip(ev.session_starts, ev.session_starts[1:])
    ]
    mean = statistics.mean(gaps)
    if mean <= 0:
        return None
    cv = statistics.pstdev(gaps) / mean
    return "regular" if cv <= REGULARITY_CV_MAX else "irregular"


def _resource_novelty(args: dict, ev: Evidence) -> str:
    inventory = ev.profile.known_slices if args["kind"] == "slice" else ev.profile.known_dnns
    return "known" if args["value"] in inventory else "novel"


def _recent_half_is_clean(ev: Evidence) -> bool:
    r = ev.recent
    return r.auth_failures == 0 and r.pdu_failures == 0 and r.spike_count == 0


def _anomaly_status(args: dict, ev: Evidence) -> str:
    flags = _flags_in_window(ev)
    if not flags:
        return "none"
    all_cleared = all(f.get("cleared_at") is not None for f in flags)
    if all_cleared or _recent_half_is_clean(ev):
        return "resolved"
    return "active"


_RULES = {
    "trend": _trend,
    "flag_age": _flag_age,
    "auth_stability": _auth_stability,
    "pdu_stability": _pdu_stability,
    "traffic_pattern": _traffic_pattern,
    "session_regularity": _session_regularity,
    "resource_novelty": _resource_novelty,
    "anomaly_status": _anomaly_status,
}


def ground(predicate: str, args: dict, evidence: Evidence) -> str | None:
    """Compute the entailed answer for a validated query, or None if the
    evidence cannot support one."""
    return _RULES[predicate](args, evidence)
