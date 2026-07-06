"""Async Postgres connection pool + CRUD operations for the IBN-ZTA schema.

Uses asyncpg for non-blocking queries. Falls back to in-memory storage
when Postgres is unavailable (development without Docker).
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger(__name__)

#these are initialized once when the application starts
_pool = None
_USE_MEMORY_FALLBACK = False


#this is just for local testing / without docker  
#it is not used when running with docker, it is just used when running the application locally
_MEMORY_STORE: dict[str, list[dict]] = {
    "ue_identity": [],
    "ue_session": [],
    "ue_risk_flag": [],
    "summary_disclosure": [],
    "budget_ledger": [],
    "negotiation_transcript": [],
}

# Serialises check-and-update on the in-memory budget ledger; Postgres gets
# the same guarantee from a conditional UPDATE instead.
_BUDGET_LOCK = asyncio.Lock()



#The StorageBackend protocol defines an interface that defines the operations that can be performed on the database. 
#It is used to define the contract between the application and the database.
#This protocol is used by the application to interact with the database.
#The application can use either the PostgresStorage class or the InMemoryStorage class to interact with the database.
class StorageBackend(Protocol):
    """Protocol defining storage operations for ZTA data."""

    async def insert_identity(
        self, pseudonym: str, imsi_hmac: str, network_b_id: str
    ) -> None:
        ...

    async def insert_session(
        self,
        pseudonym: str,
        started_at: datetime,
        ended_at: datetime | None,
        duration_sec: int | None,
        registration_success: bool,
        auth_attempts: int,
        auth_failures: int,
        pdu_attempts: int,
        pdu_failures: int,
        requested_slice: str | None,
        requested_dnn: str | None,
        bytes_uplink: int,
        bytes_downlink: int,
        peak_throughput_kbps: int | None,
        spike_count: int,
        cell_id: str | None,
        raw_log_pointer: str | None,
    ) -> int | None:
        ...

    async def get_sessions_for_ue(self, pseudonym: str, limit: int) -> list[dict]:
        ...

    async def insert_risk_flag(
        self, pseudonym: str, flag_type: str, severity: str, evidence: dict | None
    ) -> None:
        ...

    async def get_active_risk_flags(self, pseudonym: str) -> list[dict]:
        ...

    async def get_all_risk_flags(self, pseudonym: str) -> list[dict]:
        ...

    async def log_summary_disclosure(
        self,
        request_id: str,
        pseudonym: str,
        network_b_id: str,
        summary_payload: dict,
        requested_fields: list[str] | None,
    ) -> None:
        ...

    async def get_identity(self, pseudonym: str) -> dict | None:
        ...

    async def get_budget_spent(
        self, pseudonym: str, requester_id: str, window_start: int
    ) -> int:
        ...

    async def debit_budget(
        self,
        pseudonym: str,
        requester_id: str,
        window_start: int,
        cost: int,
        total: int,
    ) -> int | None:
        ...

    async def insert_transcript(
        self,
        session_id: str,
        pseudonym: str,
        requester_id: str,
        grammar_version: int,
        opened_at: datetime,
        closed_at: datetime,
        final_tier: str,
        entries: list[dict],
        transcript_hash: str,
    ) -> None:
        ...

    async def get_transcript(self, session_id: str) -> dict | None:
        ...

#This is the in-memory storage class. This is used as a fallback when the Postgres database is not available.
class InMemoryStorage:
    """Fallback storage engine using local memory store."""

    async def insert_identity(
        self, pseudonym: str, imsi_hmac: str, network_b_id: str
    ) -> None:
        for row in _MEMORY_STORE["ue_identity"]:
            if row["pseudonym"] == pseudonym:
                return
        _MEMORY_STORE["ue_identity"].append({
            "pseudonym": pseudonym,
            "imsi_hmac": imsi_hmac,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "network_b_id": network_b_id,
        })

    async def insert_session(
        self,
        pseudonym: str,
        started_at: datetime,
        ended_at: datetime | None,
        duration_sec: int | None,
        registration_success: bool,
        auth_attempts: int,
        auth_failures: int,
        pdu_attempts: int,
        pdu_failures: int,
        requested_slice: str | None,
        requested_dnn: str | None,
        bytes_uplink: int,
        bytes_downlink: int,
        peak_throughput_kbps: int | None,
        spike_count: int,
        cell_id: str | None,
        raw_log_pointer: str | None,
    ) -> int | None:
        row = {
            "pseudonym": pseudonym,
            "started_at": started_at.isoformat(),
            "ended_at": ended_at.isoformat() if ended_at else None,
            "duration_sec": duration_sec,
            "registration_success": registration_success,
            "auth_attempts": auth_attempts,
            "auth_failures": auth_failures,
            "pdu_attempts": pdu_attempts,
            "pdu_failures": pdu_failures,
            "requested_slice": requested_slice,
            "requested_dnn": requested_dnn,
            "bytes_uplink": bytes_uplink,
            "bytes_downlink": bytes_downlink,
            "peak_throughput_kbps": peak_throughput_kbps,
            "spike_count": spike_count,
            "cell_id": cell_id,
        }
        row["session_id"] = len(_MEMORY_STORE["ue_session"]) + 1
        _MEMORY_STORE["ue_session"].append(row)
        return row["session_id"]

    async def get_sessions_for_ue(self, pseudonym: str, limit: int) -> list[dict]:
        rows = [r for r in _MEMORY_STORE["ue_session"] if r["pseudonym"] == pseudonym]
        return rows[-limit:]

    async def insert_risk_flag(
        self, pseudonym: str, flag_type: str, severity: str, evidence: dict | None
    ) -> None:
        _MEMORY_STORE["ue_risk_flag"].append({
            "pseudonym": pseudonym,
            "flagged_at": datetime.now(timezone.utc).isoformat(),
            "flag_type": flag_type,
            "severity": severity,
            "evidence": evidence,
        })

    async def get_active_risk_flags(self, pseudonym: str) -> list[dict]:
        #this is getting the active risk flags for the UE pseudonym
        return [
            r for r in _MEMORY_STORE["ue_risk_flag"]
            if r["pseudonym"] == pseudonym and r.get("cleared_at") is None
        ]

    async def get_all_risk_flags(self, pseudonym: str) -> list[dict]:
        return [
            r for r in _MEMORY_STORE["ue_risk_flag"]
            if r["pseudonym"] == pseudonym
        ]

    async def log_summary_disclosure(
        self,
        request_id: str,
        pseudonym: str,
        network_b_id: str,
        summary_payload: dict,
        requested_fields: list[str] | None,
    ) -> None:
        _MEMORY_STORE["summary_disclosure"].append({
            "request_id": request_id,
            "pseudonym": pseudonym,
            "network_b_id": network_b_id,
            "disclosed_at": datetime.now(timezone.utc).isoformat(),
            "summary_payload": summary_payload,
            "requested_fields": requested_fields,
        })

    async def get_identity(self, pseudonym: str) -> dict | None:
        for row in _MEMORY_STORE["ue_identity"]:
            if row["pseudonym"] == pseudonym:
                return row
        return None

    def _budget_row(
        self, pseudonym: str, requester_id: str, window_start: int
    ) -> dict | None:
        for row in _MEMORY_STORE["budget_ledger"]:
            if (
                row["pseudonym"] == pseudonym
                and row["requester_id"] == requester_id
                and row["window_start"] == window_start
            ):
                return row
        return None

    async def get_budget_spent(
        self, pseudonym: str, requester_id: str, window_start: int
    ) -> int:
        row = self._budget_row(pseudonym, requester_id, window_start)
        return row["spent"] if row else 0

    async def debit_budget(
        self,
        pseudonym: str,
        requester_id: str,
        window_start: int,
        cost: int,
        total: int,
    ) -> int | None:
        async with _BUDGET_LOCK:
            row = self._budget_row(pseudonym, requester_id, window_start)
            if row is None:
                row = {
                    "pseudonym": pseudonym,
                    "requester_id": requester_id,
                    "window_start": window_start,
                    "spent": 0,
                }
                _MEMORY_STORE["budget_ledger"].append(row)
            if row["spent"] + cost > total:
                return None
            row["spent"] += cost
            return row["spent"]

    async def insert_transcript(
        self,
        session_id: str,
        pseudonym: str,
        requester_id: str,
        grammar_version: int,
        opened_at: datetime,
        closed_at: datetime,
        final_tier: str,
        entries: list[dict],
        transcript_hash: str,
    ) -> None:
        _MEMORY_STORE["negotiation_transcript"].append({
            "session_id": session_id,
            "pseudonym": pseudonym,
            "requester_id": requester_id,
            "grammar_version": grammar_version,
            "opened_at": opened_at.isoformat(),
            "closed_at": closed_at.isoformat(),
            "final_tier": final_tier,
            "entries": entries,
            "transcript_hash": transcript_hash,
        })

    async def get_transcript(self, session_id: str) -> dict | None:
        for row in _MEMORY_STORE["negotiation_transcript"]:
            if row["session_id"] == session_id:
                return row
        return None

#this is the production storage class. This is used when the Postgres database is available.

class PostgresStorage:
    """Production storage engine using asyncpg connection pool."""

    async def insert_identity(
        self, pseudonym: str, imsi_hmac: str, network_b_id: str
    ) -> None:
        assert _pool is not None
        await _pool.execute(
            """
            INSERT INTO ue_identity (pseudonym, imsi_hmac, first_seen, network_b_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (pseudonym) DO NOTHING
            """,
            pseudonym, imsi_hmac, datetime.now(timezone.utc), network_b_id,
        )

    async def insert_session(
        self,
        pseudonym: str,
        started_at: datetime,
        ended_at: datetime | None,
        duration_sec: int | None,
        registration_success: bool,
        auth_attempts: int,
        auth_failures: int,
        pdu_attempts: int,
        pdu_failures: int,
        requested_slice: str | None,
        requested_dnn: str | None,
        bytes_uplink: int,
        bytes_downlink: int,
        peak_throughput_kbps: int | None,
        spike_count: int,
        cell_id: str | None,
        raw_log_pointer: str | None,
    ) -> int | None:
        assert _pool is not None
        return await _pool.fetchval(
            """
            INSERT INTO ue_session (
                pseudonym, started_at, ended_at, duration_sec,
                registration_success, auth_attempts, auth_failures,
                pdu_attempts, pdu_failures, requested_slice, requested_dnn,
                bytes_uplink, bytes_downlink, peak_throughput_kbps,
                spike_count, cell_id, raw_log_pointer
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
            RETURNING session_id
            """,
            pseudonym, started_at, ended_at, duration_sec,
            registration_success, auth_attempts, auth_failures,
            pdu_attempts, pdu_failures, requested_slice, requested_dnn,
            bytes_uplink, bytes_downlink, peak_throughput_kbps,
            spike_count, cell_id, raw_log_pointer,
        )

    async def get_sessions_for_ue(self, pseudonym: str, limit: int) -> list[dict]:
        assert _pool is not None
        rows = await _pool.fetch(
            """
            SELECT * FROM ue_session
            WHERE pseudonym = $1
            ORDER BY started_at DESC
            LIMIT $2
            """,
            pseudonym, limit,
        )
        return [dict(r) for r in rows]

    async def insert_risk_flag(
        self, pseudonym: str, flag_type: str, severity: str, evidence: dict | None
    ) -> None:
        assert _pool is not None
        import json
        await _pool.execute(
            """
            INSERT INTO ue_risk_flag (pseudonym, flagged_at, flag_type, severity, evidence)
            VALUES ($1, $2, $3, $4, $5)
            """,
            pseudonym, datetime.now(timezone.utc), flag_type, severity,
            json.dumps(evidence) if evidence else None,
        )

    async def get_active_risk_flags(self, pseudonym: str) -> list[dict]:
        assert _pool is not None
        rows = await _pool.fetch(
            """
            SELECT * FROM ue_risk_flag
            WHERE pseudonym = $1 AND cleared_at IS NULL
            ORDER BY flagged_at DESC
            """,
            pseudonym,
        )
        return [dict(r) for r in rows]

    async def get_all_risk_flags(self, pseudonym: str) -> list[dict]:
        assert _pool is not None
        rows = await _pool.fetch(
            """
            SELECT * FROM ue_risk_flag
            WHERE pseudonym = $1
            ORDER BY flagged_at DESC
            """,
            pseudonym,
        )
        return [dict(r) for r in rows]

    async def log_summary_disclosure(
        self,
        request_id: str,
        pseudonym: str,
        network_b_id: str,
        summary_payload: dict,
        requested_fields: list[str] | None,
    ) -> None:
        assert _pool is not None
        import json
        await _pool.execute(
            """
            INSERT INTO summary_disclosure (request_id, pseudonym, network_b_id, disclosed_at, summary_payload, requested_fields)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            request_id, pseudonym, network_b_id, datetime.now(timezone.utc),
            json.dumps(summary_payload), requested_fields,
        )

    async def get_identity(self, pseudonym: str) -> dict | None:
        assert _pool is not None
        row = await _pool.fetchrow(
            "SELECT * FROM ue_identity WHERE pseudonym = $1",
            pseudonym,
        )
        return dict(row) if row else None

    async def get_budget_spent(
        self, pseudonym: str, requester_id: str, window_start: int
    ) -> int:
        assert _pool is not None
        spent = await _pool.fetchval(
            """
            SELECT spent FROM budget_ledger
            WHERE pseudonym = $1 AND requester_id = $2 AND window_start = $3
            """,
            pseudonym, requester_id, window_start,
        )
        return spent or 0

    async def debit_budget(
        self,
        pseudonym: str,
        requester_id: str,
        window_start: int,
        cost: int,
        total: int,
    ) -> int | None:
        assert _pool is not None
        await _pool.execute(
            """
            INSERT INTO budget_ledger (pseudonym, requester_id, window_start, spent)
            VALUES ($1, $2, $3, 0)
            ON CONFLICT (pseudonym, requester_id, window_start) DO NOTHING
            """,
            pseudonym, requester_id, window_start,
        )
        # The WHERE clause makes check-and-debit a single atomic statement:
        # it matches zero rows when the debit would overdraw.
        return await _pool.fetchval(
            """
            UPDATE budget_ledger
            SET spent = spent + $4
            WHERE pseudonym = $1 AND requester_id = $2 AND window_start = $3
              AND spent + $4 <= $5
            RETURNING spent
            """,
            pseudonym, requester_id, window_start, cost, total,
        )

    async def insert_transcript(
        self,
        session_id: str,
        pseudonym: str,
        requester_id: str,
        grammar_version: int,
        opened_at: datetime,
        closed_at: datetime,
        final_tier: str,
        entries: list[dict],
        transcript_hash: str,
    ) -> None:
        assert _pool is not None
        import json
        await _pool.execute(
            """
            INSERT INTO negotiation_transcript (
                session_id, pseudonym, requester_id, grammar_version,
                opened_at, closed_at, final_tier, entries, transcript_hash
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            """,
            session_id, pseudonym, requester_id, grammar_version,
            opened_at, closed_at, final_tier, json.dumps(entries), transcript_hash,
        )

    async def get_transcript(self, session_id: str) -> dict | None:
        assert _pool is not None
        row = await _pool.fetchrow(
            "SELECT * FROM negotiation_transcript WHERE session_id = $1",
            session_id,
        )
        return dict(row) if row else None

#this function returns the active storage engine based on the configuration.
#@functools.lru_cacsize=1) #this decorator is used to cache the result of the function, so it is only called once
def _get_backend() -> StorageBackend:
    """Resolve active storage engine based on configuration."""
    if _USE_MEMORY_FALLBACK or _pool is None:
        return InMemoryStorage()
    return PostgresStorage()


async def init_pool() -> None:
    """Initialise Postgres connection pool or enable in-memory fallback."""
    global _pool, _USE_MEMORY_FALLBACK
    try:
        import asyncpg
        _pool = await asyncpg.create_pool(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            database=os.environ.get("POSTGRES_DB", "ibn_zta"),
            user=os.environ.get("POSTGRES_USER", "ibn_zta"),
            password=os.environ.get("POSTGRES_PASSWORD", "changeme_in_production"),
            min_size=2,
            max_size=10,
        )
        logger.info("Postgres connection pool initialised")
    except Exception as exc:
        logger.warning("Postgres unavailable (%s), using in-memory fallback", exc)
        _USE_MEMORY_FALLBACK = True


async def close_pool() -> None:
    """Close active database pool connections."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def insert_identity(
    pseudonym: str,
    imsi_hmac: str,
    network_b_id: str = "Network_B",
) -> None:
    """Insert a new identity mapping."""
    backend = _get_backend()
    await backend.insert_identity(pseudonym, imsi_hmac, network_b_id)


async def insert_session(
    pseudonym: str,
    started_at: datetime,
    ended_at: datetime | None = None,
    duration_sec: int | None = None,
    registration_success: bool = True,
    auth_attempts: int = 0,
    auth_failures: int = 0,
    pdu_attempts: int = 0,
    pdu_failures: int = 0,
    requested_slice: str | None = None,
    requested_dnn: str | None = None,
    bytes_uplink: int = 0,
    bytes_downlink: int = 0,
    peak_throughput_kbps: int | None = None,
    spike_count: int = 0,
    cell_id: str | None = None,
    raw_log_pointer: str | None = None,
) -> int | None:
    """Persist a new UE session record."""
    backend = _get_backend()
    return await backend.insert_session(
        pseudonym, started_at, ended_at, duration_sec, registration_success,
        auth_attempts, auth_failures, pdu_attempts, pdu_failures,
        requested_slice, requested_dnn, bytes_uplink, bytes_downlink,
        peak_throughput_kbps, spike_count, cell_id, raw_log_pointer
    )


async def get_sessions_for_ue(
    pseudonym: str,
    limit: int = 100,
) -> list[dict]:
    """Retrieve session logs for a given UE pseudonym."""
    backend = _get_backend()
    return await backend.get_sessions_for_ue(pseudonym, limit)


async def insert_risk_flag(
    pseudonym: str,
    flag_type: str,
    severity: str,
    evidence: dict | None = None,
) -> None:
    """Log a security risk flag against a UE pseudonym."""
    backend = _get_backend()
    await backend.insert_risk_flag(pseudonym, flag_type, severity, evidence)


async def get_active_risk_flags(pseudonym: str) -> list[dict]:
    """Fetch uncleared risk flags for a specific UE pseudonym."""
    backend = _get_backend()
    return await backend.get_active_risk_flags(pseudonym)


async def get_all_risk_flags(pseudonym: str) -> list[dict]:
    """Fetch every risk flag for a UE, cleared or not (flag history)."""
    backend = _get_backend()
    return await backend.get_all_risk_flags(pseudonym)


async def log_summary_disclosure(
    request_id: str,
    pseudonym: str,
    network_b_id: str,
    summary_payload: dict,
    requested_fields: list[str] | None = None,
) -> None:
    """Record an audit trail log when a summary is disclosed."""
    backend = _get_backend()
    await backend.log_summary_disclosure(
        request_id, pseudonym, network_b_id, summary_payload, requested_fields
    )


async def get_identity(pseudonym: str) -> dict | None:
    """Look up an identity record by pseudonym."""
    backend = _get_backend()
    return await backend.get_identity(pseudonym)


async def get_budget_spent(
    pseudonym: str, requester_id: str, window_start: int
) -> int:
    """Points already spent in one (UE, requester, window) budget."""
    backend = _get_backend()
    return await backend.get_budget_spent(pseudonym, requester_id, window_start)


async def debit_budget(
    pseudonym: str,
    requester_id: str,
    window_start: int,
    cost: int,
    total: int,
) -> int | None:
    """Atomically charge ``cost`` against a window budget.

    Returns the new spent value, or None if the debit would exceed ``total``
    (in which case nothing is charged).
    """
    backend = _get_backend()
    return await backend.debit_budget(pseudonym, requester_id, window_start, cost, total)


async def insert_transcript(
    session_id: str,
    pseudonym: str,
    requester_id: str,
    grammar_version: int,
    opened_at: datetime,
    closed_at: datetime,
    final_tier: str,
    entries: list[dict],
    transcript_hash: str,
) -> None:
    """Persist a sealed negotiation transcript (the per-decision audit record)."""
    backend = _get_backend()
    await backend.insert_transcript(
        session_id, pseudonym, requester_id, grammar_version,
        opened_at, closed_at, final_tier, entries, transcript_hash,
    )


async def get_transcript(session_id: str) -> dict | None:
    """Fetch a sealed transcript by session id."""
    backend = _get_backend()
    return await backend.get_transcript(session_id)


def reset_memory_store() -> None:
    """Clear all records in the in-memory fallback store."""
    for key in _MEMORY_STORE:
        _MEMORY_STORE[key].clear()
