
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator



#Enum is a class that is used to define a set of named constants.
#this is for the AMF events.
class AmfEventType(str, Enum):
    REGISTRATION_REQUEST = "registration_request"
    AUTH_STARTED = "auth_started"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    AUTH_SQN_RESYNC = "auth_sqn_resync"
    REGISTRATION_COMPLETE = "registration_complete"
    REGISTRATION_REJECT = "registration_reject"
    PDU_REQUEST = "pdu_request"
    PDU_ACCEPT = "pdu_accept"
    PDU_REJECT = "pdu_reject"
    CONTEXT_RELEASE_REQUEST = "context_release_request"
    CONTEXT_RELEASE_COMPLETE = "context_release_complete"
    GNB_STATUS = "gnb_status"
    UE_TABLE_STATUS = "ue_table_status"
    SECURITY_MODE_COMPLETE = "security_mode_complete"

#@dataclass is a decorator that automatically generates methods for a class, such as __init__ and __repr__.
#frozen=True means that the class is immutable, i.e., it cannot be changed after it is created.
@dataclass(frozen=True)
class AmfEvent:
    timestamp: datetime
    event_type: AmfEventType
    imsi: str | None = None
    cell_id: str | None = None
    extra: dict = field(default_factory=dict)
    raw_line: str = ""

#line parser eg.[2026-06-25 19:27:21.050] [amf_app] [INFO] Registration request received from IMSI 208950000000001
#ts: 2026-06-25 19:27:21.050
#component: amf_app
#level: INFO
#msg: Registration request received from IMSI 208950000000001
_LINE_RE = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\.\d{3})\]?\s+"
    r"\[(?P<component>[\w_]+)\]\s+"
    r"\[(?P<level>\w+)\]\s+"
    r"(?P<msg>.*)$"
)

#UE table parser
_UE_TABLE_RE = re.compile(
    r"\|\s*\d+\s*\|"
    r"\s*(?P<state>5GMM-\w+)\s*\|"
    r"\s*(?P<imsi>\d{15})\s*\|"
    r"\s*(?P<guti>[0-9a-fA-F]+)\s*\|"
    r"\s*(?P<ran_id>0x[0-9a-fA-F]+)\s*\|"
    r"\s*(?P<amf_id>0x[0-9a-fA-F]+)\s*\|"
    r"\s*(?P<plmn>[\d,]+)\s*\|"
    r"\s*(?P<cell_id>[0-9a-fA-F]+)\s*\|"
)

#gNB table parser
_GNB_TABLE_RE = re.compile(
    r"\|\s*\d+\s*\|"
    r"\s*(?P<status>\w+)\s*\|"
    r"\s*(?P<gnb_id>0x[0-9a-fA-F]+)\s*\|"
    r"\s*(?P<gnb_name>[\w-]+)\s*\|"
    r"\s*(?P<plmn>[\d,]+)\s*\|"
)



#match AMF events to event types 
_PATTERNS: list[tuple[re.Pattern, AmfEventType]] = [
    (re.compile(r"Start to run Registration Procedure"),
     AmfEventType.REGISTRATION_REQUEST),

    (re.compile(r"Receive UE Authentication Request message"),
     AmfEventType.AUTH_STARTED),
    (re.compile(r"Start to generate Authentication Vectors"),
     AmfEventType.AUTH_STARTED),

    (re.compile(r"Authentication successful by network"),
     AmfEventType.AUTH_SUCCESS),
    (re.compile(r'"authResult"\s*:\s*"AUTHENTICATION_SUCCESS"'),
     AmfEventType.AUTH_SUCCESS),

    (re.compile(
        r"UE \(IMSI (?P<imsi>\d{15}),.*has been registered to the network"
    ), AmfEventType.REGISTRATION_COMPLETE),
    (re.compile(
        r"The UE's state \(IMSI (?P<imsi>\d{15}), State 5GMM-REGISTERED\)"
    ), AmfEventType.REGISTRATION_COMPLETE),

    (re.compile(r"Received Security Mode Complete message"),
     AmfEventType.SECURITY_MODE_COMPLETE),

    (re.compile(
        r"Handle PDU Session Establishment Request \(SUPI (?:imsi-)?(?P<imsi>\d{15})"
    ), AmfEventType.PDU_REQUEST),
    (re.compile(r"Received UL NAS Transport message.*handling"),
     AmfEventType.PDU_REQUEST),

    (re.compile(r"Received PDU Session Resource Setup Request message"),
     AmfEventType.PDU_ACCEPT),
    (re.compile(r"Handle PDU Session Resource Setup Response"),
     AmfEventType.PDU_ACCEPT),

    (re.compile(r"Received UE Context Release Request message"),
     AmfEventType.CONTEXT_RELEASE_REQUEST),

    (re.compile(r"Received UE Context Release Complete message"),
     AmfEventType.CONTEXT_RELEASE_COMPLETE),

    (re.compile(r"Received Authentication Failure message.*handling"),
     AmfEventType.AUTH_SQN_RESYNC),
    (re.compile(r"SQN re-?synchroni[sz]ation", re.IGNORECASE),
     AmfEventType.AUTH_SQN_RESYNC),
]


#match AMF failures to event types
_FAILURE_PATTERNS: list[tuple[re.Pattern, AmfEventType]] = [
    (re.compile(r'"authResult"\s*:\s*"AUTHENTICATION_FAILURE"'),
     AmfEventType.AUTH_FAILURE),
    (re.compile(r"Authentication\s+(?:fail|reject)", re.IGNORECASE),
     AmfEventType.AUTH_FAILURE),
    (re.compile(r"Registration\s+Reject", re.IGNORECASE),
     AmfEventType.REGISTRATION_REJECT),
    (re.compile(r"PDU Session (?:Establishment )?Reject", re.IGNORECASE),
     AmfEventType.PDU_REJECT),
]




#match IMSI and SUPI to the event
_IMSI_RE = re.compile(r"(?:IMSI|imsi-|SUPI\s+imsi-)(\d{15})")
_SUPI_RE = re.compile(r"(?:SUPI|supi)[:\s]*(?:imsi-)?(\d{15})")


#parse timestamp
def _parse_ts(raw: str) -> datetime:
    raw = raw.replace("T", " ")
    return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)




#extract imsi
def _extract_imsi(msg: str) -> str | None:
    m = _IMSI_RE.search(msg)
    if m:
        return m.group(1)
    m = _SUPI_RE.search(msg)
    return m.group(1) if m else None



#parse a line and create an AmfEvent object from the line 
def parse_line(line: str) -> AmfEvent | None:
    line = line.rstrip("\r\n")

    #check if the line is a UE table entry
    ue_m = _UE_TABLE_RE.search(line)
    #extract fields from the UE table entry
    if ue_m:
        return AmfEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AmfEventType.UE_TABLE_STATUS,
            imsi=ue_m.group("imsi"),
            cell_id=ue_m.group("cell_id"),
            extra={
                "state": ue_m.group("state"),
                "guti": ue_m.group("guti"),
                "ran_id": ue_m.group("ran_id"),
                "amf_id": ue_m.group("amf_id"),
                "plmn": ue_m.group("plmn"),
            },
            raw_line=line,
        )

    #check if the line is a gNB table entry
    gnb_m = _GNB_TABLE_RE.search(line)
    #extract fields from the gNB table entry
    if gnb_m:
        return AmfEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=AmfEventType.GNB_STATUS,
            extra={
                "status": gnb_m.group("status"),
                "gnb_id": gnb_m.group("gnb_id"),
                "gnb_name": gnb_m.group("gnb_name"),
                "plmn": gnb_m.group("plmn"),
            },
            raw_line=line,
        )

    #match AMF log messages to event types
    m = _LINE_RE.match(line)
    if not m:
        return None

    #extract timestamp, component, and message
    ts = _parse_ts(m.group("ts"))
    component = m.group("component")
    msg = m.group("msg").strip()

    #ignore non-AMF components
    if not component.startswith("amf"):
        return None

    #check for AMF events
    for pat, etype in _PATTERNS + _FAILURE_PATTERNS:
        m2 = pat.search(msg)
        if m2:
            gd = m2.groupdict()
            imsi = gd.get("imsi") or _extract_imsi(msg)
            return AmfEvent(
                timestamp=ts,
                event_type=etype,
                imsi=imsi,
                cell_id=gd.get("cell_id"),
                extra={k: v for k, v in gd.items() if k not in {"imsi", "cell_id"} and v is not None},
                raw_line=line,
            )

    return None

def parse_log_lines(lines: list[str]) -> list[AmfEvent]:
    #parse a list of AMF log lines and return a list of AmfEvent objects 
    #this function is used to parse the AMF log file and return a list of AmfEvent objects
    #each AmfEvent object contains the timestamp, event type, IMSI, cell ID, and extra information about the event
    events = []
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            events.append(ev)
    return events

def parse_stream(lines: Iterator[str]) -> Iterator[AmfEvent]:
    #parse a stream of AMF log lines and return a stream of AmfEvent objects 
    #this function is used to parse the AMF log file and return a stream of AmfEvent objects
    #each AmfEvent object contains the timestamp, event type, IMSI, cell ID, and extra information about the event
    for line in lines:
        ev = parse_line(line)
        if ev is not None:
            yield ev
