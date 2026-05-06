"""
Feature extractor: joins AMF events + UPF snapshots into session records.

Groups AMF events by IMSI, computes session metrics, merges UPF traffic data,
and writes to Postgres via db.py.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from network_a.collector.amf_log_parser import AmfEvent, AmfEventType
from network_a.collector.upf_traffic_collector import UpfSnapshot
from network_a import db


@dataclass
class SessionRecord:
    pseudonym: str
    started_at: datetime
    ended_at: datetime | None
    duration_sec: int | None
    registration_success: bool
    auth_attempts: int
    auth_failures: int
    pdu_attempts: int
    pdu_failures: int
    requested_slice: str | None
    requested_dnn: str | None
    bytes_uplink: int
    bytes_downlink: int
    peak_throughput_kbps: int | None
    spike_count: int
    cell_id: str | None


def group_events_by_imsi(events: list[AmfEvent]) -> dict[str, list[AmfEvent]]:
    grouped: dict[str, list[AmfEvent]] = defaultdict(list)
    current_imsi: str | None = None

    for ev in events:
        if ev.imsi:
            current_imsi = ev.imsi
        if current_imsi:
            grouped[current_imsi].append(ev)
    return dict(grouped)


def build_session_record(
    pseudonym: str,
    events: list[AmfEvent],
    upf: UpfSnapshot | None = None,
) -> SessionRecord:
    reg_events = [e for e in events if e.event_type in (
        AmfEventType.REGISTRATION_REQUEST, AmfEventType.REGISTRATION_COMPLETE,
    )]
    auth_events = [e for e in events if e.event_type in (
        AmfEventType.AUTH_STARTED, AmfEventType.AUTH_SUCCESS, AmfEventType.AUTH_FAILURE,
    )]
    pdu_events = [e for e in events if e.event_type in (
        AmfEventType.PDU_REQUEST, AmfEventType.PDU_ACCEPT, AmfEventType.PDU_REJECT,
    )]

    started_at = events[0].timestamp if events else datetime.now(timezone.utc)
    context_releases = [
        e for e in events
        if e.event_type in (AmfEventType.CONTEXT_RELEASE_REQUEST, AmfEventType.CONTEXT_RELEASE_COMPLETE)
    ]
    ended_at = context_releases[-1].timestamp if context_releases else None
    duration = int((ended_at - started_at).total_seconds()) if ended_at else None

    reg_success = any(
        e.event_type == AmfEventType.REGISTRATION_COMPLETE for e in reg_events
    )
    auth_failures = sum(1 for e in auth_events if e.event_type == AmfEventType.AUTH_FAILURE)
    pdu_failures = sum(1 for e in pdu_events if e.event_type == AmfEventType.PDU_REJECT)

    cell_id = None
    for e in events:
        if e.cell_id:
            cell_id = e.cell_id
            break

    return SessionRecord(
        pseudonym=pseudonym,
        started_at=started_at,
        ended_at=ended_at,
        duration_sec=duration,
        registration_success=reg_success,
        auth_attempts=len([e for e in auth_events if e.event_type in (AmfEventType.AUTH_STARTED, AmfEventType.AUTH_SUCCESS, AmfEventType.AUTH_FAILURE)]),
        auth_failures=auth_failures,
        pdu_attempts=len([e for e in pdu_events if e.event_type in (AmfEventType.PDU_REQUEST, AmfEventType.PDU_ACCEPT, AmfEventType.PDU_REJECT)]),
        pdu_failures=pdu_failures,
        requested_slice=None,
        requested_dnn=None,
        bytes_uplink=upf.bytes_uplink if upf else 0,
        bytes_downlink=upf.bytes_downlink if upf else 0,
        peak_throughput_kbps=None,
        spike_count=upf.packets_uplink if upf and False else 0,
        cell_id=cell_id,
    )


async def persist_session(record: SessionRecord) -> int | None:
    return await db.insert_session(
        pseudonym=record.pseudonym,
        started_at=record.started_at,
        ended_at=record.ended_at,
        duration_sec=record.duration_sec,
        registration_success=record.registration_success,
        auth_attempts=record.auth_attempts,
        auth_failures=record.auth_failures,
        pdu_attempts=record.pdu_attempts,
        pdu_failures=record.pdu_failures,
        requested_slice=record.requested_slice,
        requested_dnn=record.requested_dnn,
        bytes_uplink=record.bytes_uplink,
        bytes_downlink=record.bytes_downlink,
        peak_throughput_kbps=record.peak_throughput_kbps,
        spike_count=record.spike_count,
        cell_id=record.cell_id,
    )
