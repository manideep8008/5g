"""Temporal view of a UE's session history.

``build_profile`` flattens the whole window into one aggregate, which is the
right shape for bucketed summaries but erases direction: a 20% failure rate
looks identical whether the UE is deteriorating or recovering. The timeline
splits the same sessions into contiguous time buckets (oldest first) so the
trend and anomaly responders can compare "then" against "now".
"""

from __future__ import annotations

from dataclasses import dataclass

from network_a import db


@dataclass(frozen=True)
class TimelineBucket:
    session_count: int
    auth_attempts: int
    auth_failures: int
    pdu_attempts: int
    pdu_failures: int
    spike_count: int

    @property
    def auth_failure_rate(self) -> float | None:
        if self.auth_attempts == 0:
            return None
        return self.auth_failures / self.auth_attempts

    @property
    def pdu_failure_rate(self) -> float | None:
        if self.pdu_attempts == 0:
            return None
        return self.pdu_failures / self.pdu_attempts

    @property
    def spike_rate(self) -> float | None:
        if self.session_count == 0:
            return None
        return self.spike_count / self.session_count


def _aggregate(sessions: list[dict]) -> TimelineBucket:
    return TimelineBucket(
        session_count=len(sessions),
        auth_attempts=sum(s.get("auth_attempts", 0) for s in sessions),
        auth_failures=sum(s.get("auth_failures", 0) for s in sessions),
        pdu_attempts=sum(s.get("pdu_attempts", 0) for s in sessions),
        pdu_failures=sum(s.get("pdu_failures", 0) for s in sessions),
        spike_count=sum(s.get("spike_count", 0) for s in sessions),
    )


def _split(ordered: list[dict], buckets: int) -> list[list[dict]]:
    """Contiguous split into ``buckets`` chunks, oldest first.

    With 2 buckets the older half gets the smaller share on odd counts, so a
    lone session always counts as "recent" evidence rather than history.
    """
    size, remainder = divmod(len(ordered), buckets)
    chunks: list[list[dict]] = []
    start = 0
    for i in range(buckets):
        # Later (more recent) chunks absorb the remainder.
        end = start + size + (1 if i >= buckets - remainder else 0)
        chunks.append(ordered[start:end])
        start = end
    return chunks


async def build_timeline(
    pseudonym: str,
    buckets: int = 2,
    limit: int = 200,
) -> list[TimelineBucket] | None:
    """Aggregate a UE's sessions into time-ordered buckets, or None if unseen."""
    sessions = await db.get_sessions_for_ue(pseudonym, limit=limit)
    if not sessions:
        return None

    ordered = sorted(sessions, key=lambda s: s["started_at"])
    return [_aggregate(chunk) for chunk in _split(ordered, buckets)]
