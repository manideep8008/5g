"""In-memory store for live negotiation sessions.

Sessions are short-lived, single-decision state: the evidence snapshot, the
turn counter, and the transcript entries accumulated so far. Durable records
(budget ledger, sealed transcripts) live in the database — losing this store
on restart only aborts in-flight negotiations, which Network B already
treats as fail-closed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from network_a.summary.agents.evidence import Evidence

MAX_TURNS = 12
IDLE_TIMEOUT_SEC = 120


class SessionNotFound(Exception):
    """No live session with this id (never opened, closed, or expired)."""


class SessionExpired(Exception):
    """The session hit a protocol limit and was closed. ``reason`` is
    ``idle_timeout`` or ``max_turns``."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class SessionState(str, Enum):
    OPEN = "open"
    EXHAUSTED = "exhausted"


@dataclass
class Session:
    session_id: str
    ue_pseudonym: str
    requester_id: str
    grammar_version: int
    evidence: Evidence
    opened_at: datetime
    last_activity_at: datetime
    state: SessionState = SessionState.OPEN
    turns: int = 0
    entries: list[dict] = field(default_factory=list)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SessionStore:
    def __init__(
        self,
        max_turns: int = MAX_TURNS,
        idle_timeout_sec: int = IDLE_TIMEOUT_SEC,
    ):
        self.max_turns = max_turns
        self.idle_timeout_sec = idle_timeout_sec
        self._sessions: dict[str, Session] = {}

    def open(
        self,
        ue_pseudonym: str,
        requester_id: str,
        grammar_version: int,
        evidence: Evidence,
        now: datetime | None = None,
    ) -> Session:
        now = now or _utcnow()
        session = Session(
            session_id=str(uuid.uuid4()),
            ue_pseudonym=ue_pseudonym,
            requester_id=requester_id,
            grammar_version=grammar_version,
            evidence=evidence,
            opened_at=now,
            last_activity_at=now,
        )
        self._sessions[session.session_id] = session
        return session

    def begin_turn(self, session_id: str, now: datetime | None = None) -> Session:
        """Fetch a live session and account one turn against its limits.

        Raises SessionNotFound for unknown/closed ids, SessionExpired when
        this access trips the idle timeout or the turn cap (the session is
        closed as a side effect — protocol limits are terminal).
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound(session_id)

        now = now or _utcnow()
        idle = (now - session.last_activity_at).total_seconds()
        if idle > self.idle_timeout_sec:
            del self._sessions[session_id]
            raise SessionExpired("idle_timeout")

        session.turns += 1
        if session.turns > self.max_turns:
            del self._sessions[session_id]
            raise SessionExpired("max_turns")

        session.last_activity_at = now
        return session

    def close(self, session_id: str) -> Session:
        """Remove and return the session; raises SessionNotFound if absent."""
        session = self._sessions.pop(session_id, None)
        if session is None:
            raise SessionNotFound(session_id)
        return session

    def clear(self) -> None:
        """Drop all live sessions (test isolation)."""
        self._sessions.clear()
