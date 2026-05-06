"""Tests for feature extractor — grouping events and building session records."""

from network_a.collector.amf_log_parser import AmfEventType, parse_log_lines
from network_a.collector.feature_extractor import build_session_record, group_events_by_imsi
from network_a.collector.upf_traffic_collector import UpfSnapshot

import time


FULL_SESSION_LINES = [
    "2025-01-05 01:02:20.000 [amf_app] [info] New UE Registration Request",
    "2025-01-05 01:02:20.100 [amf_app] [info] UE Authentication Started for IMSI: 208950000000031",
    "2025-01-05 01:02:20.500 [amf_app] [info] UE Authentication Successful for IMSI: 208950000000031",
    "2025-01-05 01:02:21.100 [amf_app] [info] IMSI: 208950000000031, 5GMM State: REGISTERED, GUTI: 208950000000031, Cell ID: 0x00000001",
    "2025-01-05 01:02:25.000 [amf_app] [info] PDU Session Establishment Request received",
    "2025-01-05 01:02:25.300 [amf_app] [info] PDU Session Establishment Accept sent to UE",
    "2025-01-05 01:02:50.000 [amf_app] [info] UE Context Release Request received from gNB",
    "2025-01-05 01:02:50.500 [amf_app] [info] UE Context Release Complete received from gNB",
]


class TestGroupEventsByImsi:
    def test_single_imsi(self):
        events = parse_log_lines(FULL_SESSION_LINES)
        grouped = group_events_by_imsi(events)
        assert "208950000000031" in grouped
        # REGISTRATION_REQUEST has no IMSI so it's excluded until an IMSI-bearing event sets current_imsi
        assert len(grouped["208950000000031"]) == 7

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
        assert record.cell_id == "0x00000001"
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
            "2025-01-05 01:02:20.100 [amf_app] [info] UE Authentication Started for IMSI: 208950000000031",
            "2025-01-05 01:02:20.500 [amf_app] [info] UE Authentication Failed for IMSI: 208950000000031",
            "2025-01-05 01:02:50.000 [amf_app] [info] UE Context Release Request received from gNB",
        ]
        events = parse_log_lines(lines)
        record = build_session_record("UE_HASH_001", events)
        assert record.auth_failures == 1
        assert record.registration_success is False
