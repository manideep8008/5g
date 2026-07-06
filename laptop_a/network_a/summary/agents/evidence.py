"""The evidence bundle responder agents reason over.

Assembled once per negotiation session so every answer in a session is
computed from one consistent snapshot, and curated on purpose: agents see
derived aggregates (profile, timeline halves, flag rows, session start
times), never raw log lines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from network_a import db
from network_a.summary.summary_generator import UeProfile, build_profile
from network_a.summary.timeline import TimelineBucket, build_timeline

DEFAULT_WINDOW_SEC = 86400
_SESSION_LIMIT = 200


def as_datetime(value: str | datetime | None) -> datetime | None:
    """Normalize timestamps: Postgres returns datetimes, the in-memory
    store returns isoformat strings."""
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


@dataclass(frozen=True)
class Evidence:
    profile: UeProfile
    older: TimelineBucket
    recent: TimelineBucket
    flags: list[dict] = field(default_factory=list)
    session_starts: list[datetime] = field(default_factory=list)
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    window_sec: int = DEFAULT_WINDOW_SEC


async def gather_evidence(
    pseudonym: str,
    window_sec: int = DEFAULT_WINDOW_SEC,
    now: datetime | None = None,
) -> Evidence | None:
    """Snapshot everything the responders may consult, or None if the UE
    has no session history."""
    profile = await build_profile(pseudonym, window_sec=window_sec)
    if profile is None:
        return None

    older, recent = await build_timeline(pseudonym, buckets=2, limit=_SESSION_LIMIT)
    flags = await db.get_all_risk_flags(pseudonym)
    sessions = await db.get_sessions_for_ue(pseudonym, limit=_SESSION_LIMIT)
    starts = sorted(
        ts for s in sessions if (ts := as_datetime(s.get("started_at"))) is not None
    )

    return Evidence(
        profile=profile,
        older=older,
        recent=recent,
        flags=flags,
        session_starts=starts,
        now=now or datetime.now(timezone.utc),
        window_sec=window_sec,
    )
