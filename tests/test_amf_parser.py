"""Tests for AMF log parser against real OAI CN5G 'manual' log format."""

from network_a.collector.amf_log_parser import AmfEventType, parse_line, parse_log_lines


SAMPLE_REG_REQUEST = "2025-01-05 01:02:20.000 [amf_app] [info] New UE Registration Request"
SAMPLE_AUTH_STARTED = "2025-01-05 01:02:20.100 [amf_app] [info] UE Authentication Started for IMSI: 208950000000031"
SAMPLE_AUTH_SUCCESS = "2025-01-05 01:02:20.500 [amf_app] [info] UE Authentication Successful for IMSI: 208950000000031"
SAMPLE_AUTH_FAILURE = "2025-01-05 01:02:20.500 [amf_app] [info] UE Authentication Failed for IMSI: 208950000000031"
SAMPLE_REG_COMPLETE = "2025-01-05 01:02:21.100 [amf_app] [info] IMSI: 208950000000031, 5GMM State: REGISTERED, GUTI: 208950000000031, Cell ID: 0x00000001"
SAMPLE_PDU_REQUEST = "2025-01-05 01:02:25.000 [amf_app] [info] PDU Session Establishment Request received"
SAMPLE_PDU_ACCEPT = "2025-01-05 01:02:25.300 [amf_app] [info] PDU Session Establishment Accept sent to UE"
SAMPLE_PDU_REJECT = "2025-01-05 01:02:25.300 [amf_app] [info] PDU Session Establishment Reject"
SAMPLE_CTX_REL_REQ = "2025-01-05 01:02:50.000 [amf_app] [info] UE Context Release Request received from gNB"
SAMPLE_CTX_REL_COMP = "2025-01-05 01:02:50.500 [amf_app] [info] UE Context Release Complete received from gNB"
SAMPLE_COUNTER = "2025-01-05 01:02:35.000 [amf_app] [info] Connected UEs: 1, Active PDU Sessions: 1, Connected gNBs: 1"
SAMPLE_NO_UES = "2025-01-05 01:03:10.000 [amf_app] [info] No UEs currently connected"
SAMPLE_GNB = "2025-01-05 01:03:20.000 [amf_app] [info] gNB-Eurecom-CU (ID: 0x000000E0) Status: Connected PLMN: 20895"
SAMPLE_SBI_LINE = "2025-01-05 01:00:08.957 [amf_sbi] [debug] Send NF Update to NRF, Msg body [...]"
SAMPLE_GARBAGE = "some random text that is not a log line"


class TestAmfLogParser:
    def test_parse_registration_request(self):
        ev = parse_line(SAMPLE_REG_REQUEST)
        assert ev is not None
        assert ev.event_type == AmfEventType.REGISTRATION_REQUEST
        assert ev.imsi is None

    def test_parse_auth_started(self):
        ev = parse_line(SAMPLE_AUTH_STARTED)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_STARTED
        assert ev.imsi == "208950000000031"

    def test_parse_auth_success(self):
        ev = parse_line(SAMPLE_AUTH_SUCCESS)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_SUCCESS
        assert ev.imsi == "208950000000031"

    def test_parse_auth_failure(self):
        ev = parse_line(SAMPLE_AUTH_FAILURE)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_FAILURE
        assert ev.imsi == "208950000000031"

    def test_parse_registration_complete(self):
        ev = parse_line(SAMPLE_REG_COMPLETE)
        assert ev is not None
        assert ev.event_type == AmfEventType.REGISTRATION_COMPLETE
        assert ev.imsi == "208950000000031"
        assert ev.cell_id == "0x00000001"

    def test_parse_pdu_request(self):
        ev = parse_line(SAMPLE_PDU_REQUEST)
        assert ev is not None
        assert ev.event_type == AmfEventType.PDU_REQUEST

    def test_parse_pdu_accept(self):
        ev = parse_line(SAMPLE_PDU_ACCEPT)
        assert ev is not None
        assert ev.event_type == AmfEventType.PDU_ACCEPT

    def test_parse_pdu_reject(self):
        ev = parse_line(SAMPLE_PDU_REJECT)
        assert ev is not None
        assert ev.event_type == AmfEventType.PDU_REJECT

    def test_parse_context_release_request(self):
        ev = parse_line(SAMPLE_CTX_REL_REQ)
        assert ev is not None
        assert ev.event_type == AmfEventType.CONTEXT_RELEASE_REQUEST

    def test_parse_context_release_complete(self):
        ev = parse_line(SAMPLE_CTX_REL_COMP)
        assert ev is not None
        assert ev.event_type == AmfEventType.CONTEXT_RELEASE_COMPLETE

    def test_parse_counter_snapshot(self):
        ev = parse_line(SAMPLE_COUNTER)
        assert ev is not None
        assert ev.event_type == AmfEventType.COUNTER_SNAPSHOT
        assert ev.extra["ues"] == "1"
        assert ev.extra["sessions"] == "1"

    def test_parse_no_ues(self):
        ev = parse_line(SAMPLE_NO_UES)
        assert ev is not None
        assert ev.event_type == AmfEventType.NO_UES

    def test_parse_gnb_status(self):
        ev = parse_line(SAMPLE_GNB)
        assert ev is not None
        assert ev.event_type == AmfEventType.GNB_STATUS
        assert ev.extra["gnb_id"] == "0x000000E0"
        assert ev.extra["status"] == "Connected"

    def test_sbi_line_ignored(self):
        assert parse_line(SAMPLE_SBI_LINE) is None

    def test_garbage_line_ignored(self):
        assert parse_line(SAMPLE_GARBAGE) is None

    def test_parse_full_session(self):
        lines = [
            SAMPLE_REG_REQUEST,
            SAMPLE_AUTH_STARTED,
            SAMPLE_AUTH_SUCCESS,
            SAMPLE_REG_COMPLETE,
            SAMPLE_PDU_REQUEST,
            SAMPLE_PDU_ACCEPT,
            SAMPLE_COUNTER,
            SAMPLE_CTX_REL_REQ,
            SAMPLE_CTX_REL_COMP,
            SAMPLE_SBI_LINE,
        ]
        events = parse_log_lines(lines)
        assert len(events) == 9
        types = [e.event_type for e in events]
        assert AmfEventType.REGISTRATION_REQUEST in types
        assert AmfEventType.AUTH_SUCCESS in types
        assert AmfEventType.REGISTRATION_COMPLETE in types
        assert AmfEventType.PDU_ACCEPT in types
        assert AmfEventType.CONTEXT_RELEASE_COMPLETE in types

    def test_timestamp_parsing(self):
        ev = parse_line(SAMPLE_AUTH_STARTED)
        assert ev.timestamp.year == 2025
        assert ev.timestamp.month == 1
        assert ev.timestamp.day == 5
        assert ev.timestamp.hour == 1
        assert ev.timestamp.minute == 2
        assert ev.timestamp.second == 20
