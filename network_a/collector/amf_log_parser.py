"""
AMF log parser for OAI CN5G "manual" log format.

Tested against the format:
    2025-01-05 01:02:20.100 [amf_app] [info] UE Authentication Started for IMSI: 208950000000031

Only emits events for lines it recognises with high confidence.
Unrecognised lines return None.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator


class AmfEventType(str, Enum):
    REGISTRATION_REQUEST = "registration_request"
    AUTH_STARTED = "auth_started"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    REGISTRATION_COMPLETE = "registration_complete"
    REGISTRATION_REJECT = "registration_reject"
    PDU_REQUEST = "pdu_request"
    PDU_ACCEPT = "pdu_accept"
    PDU_REJECT = "pdu_reject"
    CONTEXT_RELEASE_REQUEST = "context_release_request"
    CONTEXT_RELEASE_COMPLETE = "context_release_complete"
    GNB_STATUS = "gnb_status"
    COUNTER_SNAPSHOT = "counter_snapshot"
    NO_UES = "no_ues_connected"


@dataclass(frozen=True)
class AmfEvent:
    timestamp: datetime
    event_type: AmfEventType
    imsi: str | None = None
    cell_id: str | None = None
    extra: dict = field(default_factory=dict)
    raw_line: str = ""


_LINE_RE = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d{3})\]?\s+"
    r"\[(?P<component>[\w_]+)\]\s+"
    r"\[(?P<level>\w+)\]\s+"
    r"(?P<msg>.*)$"
)

_PATTERNS: list[tuple[re.Pattern, AmfEventType]] = [
    (re.compile(r"^New UE Registration Request"),
     AmfEventType.REGISTRATION_REQUEST),
    (re.compile(r"Received\s+InitialUEMessage", re.IGNORECASE),
     AmfEventType.REGISTRATION_REQUEST),
    (re.compile(r"^UE Authentication Started for IMSI:\s*(?P<imsi>\d+)"),
     AmfEventType.AUTH_STARTED),
    (re.compile(r"Authentication\s+(?:with|procedure|vector).*?(?:SUPI|IMSI)[:\s]+(?P<imsi>\d+)", re.IGNORECASE),
     AmfEventType.AUTH_STARTED),
    (re.compile(r"^UE Authentication Successful for IMSI:\s*(?P<imsi>\d+)"),
     AmfEventType.AUTH_SUCCESS),
    (re.compile(r"Authentication\s+(?:successful|success).*?(?:SUPI|IMSI)[:\s]+(?P<imsi>\d+)", re.IGNORECASE),
     AmfEventType.AUTH_SUCCESS),
    (re.compile(
        r"^IMSI:\s*(?P<imsi>\d+),\s*5GMM State:\s*REGISTERED.*"
        r"Cell ID:\s*(?P<cell_id>0x[0-9a-fA-F]+)"
    ), AmfEventType.REGISTRATION_COMPLETE),
    (re.compile(r"5GMM[- ]?state.*REGISTERED.*?(?:SUPI|IMSI)[:\s]+(?P<imsi>\d+)", re.IGNORECASE),
     AmfEventType.REGISTRATION_COMPLETE),
    (re.compile(r"Registration\s+(?:Complete|Accept).*?(?:SUPI|IMSI)[:\s]+(?P<imsi>\d+)", re.IGNORECASE),
     AmfEventType.REGISTRATION_COMPLETE),
    (re.compile(r"^PDU Session Establishment Request received"),
     AmfEventType.PDU_REQUEST),
    (re.compile(r"Received.*PDU\s+Session\s+(?:Establishment\s+)?Request", re.IGNORECASE),
     AmfEventType.PDU_REQUEST),
    (re.compile(r"^PDU Session Establishment Accept sent to UE"),
     AmfEventType.PDU_ACCEPT),
    (re.compile(r"PDU\s+Session\s+(?:Establishment\s+)?Accept", re.IGNORECASE),
     AmfEventType.PDU_ACCEPT),
    (re.compile(r"^UE Context Release Request received from gNB"),
     AmfEventType.CONTEXT_RELEASE_REQUEST),
    (re.compile(r"UE\s+Context\s+Release\s+(?:Request|Command)", re.IGNORECASE),
     AmfEventType.CONTEXT_RELEASE_REQUEST),
    (re.compile(r"^UE Context Release Complete received from gNB"),
     AmfEventType.CONTEXT_RELEASE_COMPLETE),
    (re.compile(r"UE\s+Context\s+Release\s+Complete", re.IGNORECASE),
     AmfEventType.CONTEXT_RELEASE_COMPLETE),
    (re.compile(
        r"^Connected UEs:\s*(?P<ues>\d+),\s*Active PDU Sessions:\s*(?P<sessions>\d+),\s*Connected gNBs:\s*(?P<gnbs>\d+)"
    ), AmfEventType.COUNTER_SNAPSHOT),
    (re.compile(r"^No UEs currently connected"),
     AmfEventType.NO_UES),
    (re.compile(
        r"^gNB-\S+\s+\(ID:\s*(?P<gnb_id>0x[0-9a-fA-F]+)\)\s+Status:\s*(?P<status>\w+)\s+PLMN:\s*(?P<plmn>[\d,]+)"
    ), AmfEventType.GNB_STATUS),
    (re.compile(r"Received\s+NG\s+Setup\s+Request", re.IGNORECASE),
     AmfEventType.GNB_STATUS),
]

_FAILURE_PATTERNS: list[tuple[re.Pattern, AmfEventType]] = [
    (re.compile(r"^UE Authentication Failed for IMSI:\s*(?P<imsi>\d+)"),
     AmfEventType.AUTH_FAILURE),
    (re.compile(r"Authentication\s+(?:fail|reject).*?(?:SUPI|IMSI)[:\s]+(?P<imsi>\d+)", re.IGNORECASE),
     AmfEventType.AUTH_FAILURE),
    (re.compile(r"Registration\s+Reject", re.IGNORECASE),
     AmfEventType.REGISTRATION_REJECT),
    (re.compile(r"PDU Session Establishment Reject"),
     AmfEventType.PDU_REJECT),
]


def _parse_ts(raw: str) -> datetime:
    raw = raw.replace("T", " ")
    return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)


def parse_line(line: str) -> AmfEvent | None:
    line = line.rstrip("\r\n")
    m = _LINE_RE.match(line)
    if not m:
        return None

    ts = _parse_ts(m.group("ts"))
    msg = m.group("msg").strip()

    if not m.group("component").startswith("amf"):
        return None

    for pat, etype in _PATTERNS + _FAILURE_PATTERNS:
        m2 = pat.search(msg)
        if m2:
            gd = m2.groupdict()
            imsi = gd.get("imsi")
            if not imsi:
                imsi = _extract_supi(msg)
            return AmfEvent(
                timestamp=ts,
                event_type=etype,
                imsi=imsi,
                cell_id=gd.get("cell_id"),
                extra={k: v for k, v in gd.items() if k not in {"imsi", "cell_id"} and v is not None},
                raw_line=line,
            )

    return None


_SUPI_RE = re.compile(r"(?:SUPI|supi)[:\s]*(?:imsi-)?(\d{15})")


def _extract_supi(msg: str) -> str | None:
    m = _SUPI_RE.search(msg)
    return m.group(1) if m else None


def parse_log_lines(lines: list[str]) -> list[AmfEvent]:
    return [ev for line in lines if (ev := parse_line(line)) is not None]


def parse_stream(lines: Iterator[str]) -> Iterator[AmfEvent]:
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev
