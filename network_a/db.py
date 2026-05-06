"""
Async Postgres connection pool + CRUD operations for the IBN-ZTA schema.

Uses asyncpg for non-blocking queries. Falls back to in-memory storage
when Postgres is unavailable (development without Docker).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_pool = None
_USE_MEMORY_FALLBACK = False
_MEMORY_STORE: dict[str, list[dict]] = {
    "ue_identity": [],
    "ue_session": [],
    "ue_risk_flag": [],
    "summary_disclosure": [],
}


async def init_pool() -> None:
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
        logger.info("Postgres pool initialised")
    except Exception as e:
        logger.warning("Postgres unavailable (%s), using in-memory fallback", e)
        _USE_MEMORY_FALLBACK = True


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def insert_identity(
    pseudonym: str,
    imsi_hmac: str,
    network_b_id: str = "Network_B",
) -> None:
    if _USE_MEMORY_FALLBACK:
        for row in _MEMORY_STORE["ue_identity"]:
            if row["pseudonym"] == pseudonym:
                return
        _MEMORY_STORE["ue_identity"].append({
            "pseudonym": pseudonym,
            "imsi_hmac": imsi_hmac,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "network_b_id": network_b_id,
        })
        return

    await _pool.execute(
        """
        INSERT INTO ue_identity (pseudonym, imsi_hmac, first_seen, network_b_id)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (pseudonym) DO NOTHING
        """,
        pseudonym, imsi_hmac, datetime.now(timezone.utc), network_b_id,
    )


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

    if _USE_MEMORY_FALLBACK:
        row["session_id"] = len(_MEMORY_STORE["ue_session"]) + 1
        _MEMORY_STORE["ue_session"].append(row)
        return row["session_id"]

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


async def get_sessions_for_ue(
    pseudonym: str,
    limit: int = 100,
) -> list[dict]:
    if _USE_MEMORY_FALLBACK:
        rows = [r for r in _MEMORY_STORE["ue_session"] if r["pseudonym"] == pseudonym]
        return rows[-limit:]

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
    pseudonym: str,
    flag_type: str,
    severity: str,
    evidence: dict | None = None,
) -> None:
    if _USE_MEMORY_FALLBACK:
        _MEMORY_STORE["ue_risk_flag"].append({
            "pseudonym": pseudonym,
            "flagged_at": datetime.now(timezone.utc).isoformat(),
            "flag_type": flag_type,
            "severity": severity,
            "evidence": evidence,
        })
        return

    import json
    await _pool.execute(
        """
        INSERT INTO ue_risk_flag (pseudonym, flagged_at, flag_type, severity, evidence)
        VALUES ($1, $2, $3, $4, $5)
        """,
        pseudonym, datetime.now(timezone.utc), flag_type, severity,
        json.dumps(evidence) if evidence else None,
    )


async def get_active_risk_flags(pseudonym: str) -> list[dict]:
    if _USE_MEMORY_FALLBACK:
        return [
            r for r in _MEMORY_STORE["ue_risk_flag"]
            if r["pseudonym"] == pseudonym and r.get("cleared_at") is None
        ]

    rows = await _pool.fetch(
        """
        SELECT * FROM ue_risk_flag
        WHERE pseudonym = $1 AND cleared_at IS NULL
        ORDER BY flagged_at DESC
        """,
        pseudonym,
    )
    return [dict(r) for r in rows]


async def log_summary_disclosure(
    request_id: str,
    pseudonym: str,
    network_b_id: str,
    summary_payload: dict,
    requested_fields: list[str] | None = None,
) -> None:
    import json

    if _USE_MEMORY_FALLBACK:
        _MEMORY_STORE["summary_disclosure"].append({
            "request_id": request_id,
            "pseudonym": pseudonym,
            "network_b_id": network_b_id,
            "disclosed_at": datetime.now(timezone.utc).isoformat(),
            "summary_payload": summary_payload,
            "requested_fields": requested_fields,
        })
        return

    await _pool.execute(
        """
        INSERT INTO summary_disclosure (request_id, pseudonym, network_b_id, disclosed_at, summary_payload, requested_fields)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        request_id, pseudonym, network_b_id, datetime.now(timezone.utc),
        json.dumps(summary_payload), requested_fields,
    )


async def get_identity(pseudonym: str) -> dict | None:
    if _USE_MEMORY_FALLBACK:
        for row in _MEMORY_STORE["ue_identity"]:
            if row["pseudonym"] == pseudonym:
                return row
        return None

    row = await _pool.fetchrow(
        "SELECT * FROM ue_identity WHERE pseudonym = $1",
        pseudonym,
    )
    return dict(row) if row else None


def reset_memory_store() -> None:
    for key in _MEMORY_STORE:
        _MEMORY_STORE[key].clear()
