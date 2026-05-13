"""Tests for feature extractor — grouping events and building session records."""

from network_a.collector.amf_log_parser import AmfEventType, parse_log_lines
from network_a.collector.feature_extractor import build_session_record, group_events_by_imsi
from network_a.collector.upf_traffic_collector import UpfSnapshot

import time


FULL_SESSION_LINES = [
    "[2026-05-13 18:42:20.768] [amf_n1] [debug] Start to run Registration Procedure",
    "[2026-05-13 18:42:20.778] [amf_n1] [debug] Start to generate Authentication Vectors",
    "[2026-05-13 18:42:20.779] [amf_sbi] [info] Receive UE Authentication Request message, handling ...",
    "[2026-05-13 18:42:20.901] [amf_n1] [debug] Authentication successful by network!",
    '[2026-05-13 18:42:20.901] [amf_n1] [debug] Got ConfirmationDataResponse from AUSF: {"authResult":"AUTHENTICATION_SUCCESS","supi":"imsi-001010000000001"}',
    "[2026-05-13 18:42:20.918] [amf_n1] [info] UE (IMSI 001010000000001, GUTI 001010100411274052588, current RAN ID 2, current AMF ID 2) has been registered to the network",
    "[2026-05-13 18:42:21.240] [amf_sbi] [debug] Handle PDU Session Establishment Request (SUPI imsi-001010000000001, PDU Session ID 5)",
    "[2026-05-13 18:42:21.245] [amf_n2] [info] Received PDU Session Resource Setup Request message, handling",
    "[2026-05-13 18:42:55.427] [amf_n2] [info] Received UE Context Release Request message, handling",
    "[2026-05-13 18:42:55.428] [amf_n2] [info] Received UE Context Release Complete message, handling",
]


class TestGroupEventsByImsi:
    def test_single_imsi(self):
        events = parse_log_lines(FULL_SESSION_LINES)
        grouped = group_events_by_imsi(events)
        assert "001010000000001" in grouped
        assert len(grouped["001010000000001"]) >= 5

    def test_empty_events(self):
        grouped = group_events_by_imsi([])
        assert grouped == {}


class TestBuildSessionRecord:
    def test_full_session(self):
        events = parse_log_lines(FULL_SESSION_LINES)
        record = build_session_record("UE_HASH_001", events)
        assert record.pseudonym == "UE_HASH_001"
        assert record.registration_success is True
        assert record.auth_attempts >= 2
        assert record.auth_failures == 0
        assert record.pdu_attempts >= 1
        assert record.pdu_failures == 0
        assert record.ended_at is not None
        assert record.duration_sec is not None
        assert record.duration_sec > 0

    def test_session_with_upf(self):
        events = parse_log_lines(FULL_SESSION_LINES)
        upf = UpfSnapshot(
            ts=time.time(),
            ue_ip="12.1.1.2",
            bytes_uplink=5000,
            bytes_downlink=25000,
            packets_uplink=50,
            packets_downlink=200,
            pfcp_session_active=True,
        )
        record = build_session_record("UE_HASH_001", events, upf=upf)
        assert record.bytes_uplink == 5000
        assert record.bytes_downlink == 25000

    def test_session_with_auth_failure(self):
        lines = [
            "[2026-05-13 18:42:20.778] [amf_n1] [debug] Start to generate Authentication Vectors",
            '[2026-05-13 18:42:20.901] [amf_n1] [debug] Got ConfirmationDataResponse from AUSF: {"authResult":"AUTHENTICATION_FAILURE","supi":"imsi-001010000000001"}',
            "[2026-05-13 18:42:55.427] [amf_n2] [info] Received UE Context Release Request message, handling",
        ]
        events = parse_log_lines(lines)
        record = build_session_record("UE_HASH_001", events)
        assert record.auth_failures == 1
        assert record.registration_success is False
