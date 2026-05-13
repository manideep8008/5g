"""Tests for AMF log parser against real OAI CN5G v2.2.1 log format."""

from network_a.collector.amf_log_parser import AmfEventType, parse_line, parse_log_lines


SAMPLE_REG_REQUEST = "[2026-05-13 18:42:20.768] [amf_n1] [debug] Start to run Registration Procedure"
SAMPLE_AUTH_STARTED = "[2026-05-13 18:42:20.779] [amf_sbi] [info] Receive UE Authentication Request message, handling ..."
SAMPLE_AUTH_STARTED_ALT = "[2026-05-13 18:42:20.778] [amf_n1] [debug] Start to generate Authentication Vectors"
SAMPLE_AUTH_SUCCESS = '[2026-05-13 18:42:20.901] [amf_n1] [debug] Got ConfirmationDataResponse from AUSF: {"authResult":"AUTHENTICATION_SUCCESS","supi":"imsi-001010000000001"}'
SAMPLE_AUTH_SUCCESS_ALT = "[2026-05-13 18:42:20.901] [amf_n1] [debug] Authentication successful by network!"
SAMPLE_AUTH_FAILURE = '[2026-05-13 18:42:20.901] [amf_n1] [debug] Got ConfirmationDataResponse from AUSF: {"authResult":"AUTHENTICATION_FAILURE","supi":"imsi-001010000000001"}'
SAMPLE_REG_COMPLETE = "[2026-05-13 18:42:20.918] [amf_n1] [info] UE (IMSI 001010000000001, GUTI 001010100411274052588, current RAN ID 2, current AMF ID 2) has been registered to the network"
SAMPLE_REG_COMPLETE_ALT = "[2026-05-13 18:42:20.918] [amf_app] [debug] The UE's state (IMSI 001010000000001, State 5GMM-REGISTERED) has been successfully updated!"
SAMPLE_SEC_MODE = "[2026-05-13 18:42:20.913] [amf_n1] [debug] Received Security Mode Complete message, handling..."
SAMPLE_PDU_REQUEST = "[2026-05-13 18:42:21.240] [amf_sbi] [debug] Handle PDU Session Establishment Request (SUPI imsi-001010000000001, PDU Session ID 5)"
SAMPLE_PDU_ACCEPT = "[2026-05-13 18:42:21.245] [amf_n2] [info] Received PDU Session Resource Setup Request message, handling"
SAMPLE_CTX_REL_REQ = "[2026-05-13 18:42:55.427] [amf_n2] [info] Received UE Context Release Request message, handling"
SAMPLE_CTX_REL_COMP = "[2026-05-13 18:42:55.428] [amf_n2] [info] Received UE Context Release Complete message, handling"
SAMPLE_GNB_TABLE = "   |    1   |              Connected             |               0x0E00               |               gNB-OAI              |               001,01               |"
SAMPLE_UE_TABLE = "   |    1   |   5GMM-REGISTERED  |             001010000000001            |00101010041127405258|        0x02        |        0x02        |       001,01       |      0000e014e     |"
SAMPLE_NAS_LINE = "[2026-05-13 18:42:20.778] [nas] [debug] Decoding 5GSMobilityIdentity SUCI"
SAMPLE_HEARTBEAT = "[2026-05-13 18:42:27.672] [amf_sbi] [debug] Send NF Update to NRF"
SAMPLE_GARBAGE = "some random text that is not a log line"


class TestAmfLogParser:
    def test_parse_registration_request(self):
        ev = parse_line(SAMPLE_REG_REQUEST)
        assert ev is not None
        assert ev.event_type == AmfEventType.REGISTRATION_REQUEST

    def test_parse_auth_started(self):
        ev = parse_line(SAMPLE_AUTH_STARTED)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_STARTED

    def test_parse_auth_started_alt(self):
        ev = parse_line(SAMPLE_AUTH_STARTED_ALT)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_STARTED

    def test_parse_auth_success(self):
        ev = parse_line(SAMPLE_AUTH_SUCCESS)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_SUCCESS
        assert ev.imsi == "001010000000001"

    def test_parse_auth_success_alt(self):
        ev = parse_line(SAMPLE_AUTH_SUCCESS_ALT)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_SUCCESS

    def test_parse_auth_failure(self):
        ev = parse_line(SAMPLE_AUTH_FAILURE)
        assert ev is not None
        assert ev.event_type == AmfEventType.AUTH_FAILURE

    def test_parse_registration_complete(self):
        ev = parse_line(SAMPLE_REG_COMPLETE)
        assert ev is not None
        assert ev.event_type == AmfEventType.REGISTRATION_COMPLETE
        assert ev.imsi == "001010000000001"

    def test_parse_registration_complete_alt(self):
        ev = parse_line(SAMPLE_REG_COMPLETE_ALT)
        assert ev is not None
        assert ev.event_type == AmfEventType.REGISTRATION_COMPLETE
        assert ev.imsi == "001010000000001"

    def test_parse_security_mode_complete(self):
        ev = parse_line(SAMPLE_SEC_MODE)
        assert ev is not None
        assert ev.event_type == AmfEventType.SECURITY_MODE_COMPLETE

    def test_parse_pdu_request(self):
        ev = parse_line(SAMPLE_PDU_REQUEST)
        assert ev is not None
        assert ev.event_type == AmfEventType.PDU_REQUEST
        assert ev.imsi == "001010000000001"

    def test_parse_pdu_accept(self):
        ev = parse_line(SAMPLE_PDU_ACCEPT)
        assert ev is not None
        assert ev.event_type == AmfEventType.PDU_ACCEPT

    def test_parse_context_release_request(self):
        ev = parse_line(SAMPLE_CTX_REL_REQ)
        assert ev is not None
        assert ev.event_type == AmfEventType.CONTEXT_RELEASE_REQUEST

    def test_parse_context_release_complete(self):
        ev = parse_line(SAMPLE_CTX_REL_COMP)
        assert ev is not None
        assert ev.event_type == AmfEventType.CONTEXT_RELEASE_COMPLETE

    def test_parse_gnb_table_row(self):
        ev = parse_line(SAMPLE_GNB_TABLE)
        assert ev is not None
        assert ev.event_type == AmfEventType.GNB_STATUS
        assert ev.extra["gnb_id"] == "0x0E00"
        assert ev.extra["gnb_name"] == "gNB-OAI"
        assert ev.extra["status"] == "Connected"

    def test_parse_ue_table_row(self):
        ev = parse_line(SAMPLE_UE_TABLE)
        assert ev is not None
        assert ev.event_type == AmfEventType.UE_TABLE_STATUS
        assert ev.imsi == "001010000000001"
        assert ev.cell_id == "0000e014e"
        assert ev.extra["state"] == "5GMM-REGISTERED"

    def test_nas_line_ignored(self):
        assert parse_line(SAMPLE_NAS_LINE) is None

    def test_heartbeat_ignored(self):
        assert parse_line(SAMPLE_HEARTBEAT) is None

    def test_garbage_line_ignored(self):
        assert parse_line(SAMPLE_GARBAGE) is None

    def test_parse_full_session(self):
        lines = [
            SAMPLE_REG_REQUEST,
            SAMPLE_AUTH_STARTED,
            SAMPLE_AUTH_SUCCESS_ALT,
            SAMPLE_REG_COMPLETE,
            SAMPLE_SEC_MODE,
            SAMPLE_GNB_TABLE,
            SAMPLE_UE_TABLE,
            SAMPLE_PDU_REQUEST,
            SAMPLE_PDU_ACCEPT,
            SAMPLE_CTX_REL_REQ,
            SAMPLE_CTX_REL_COMP,
            SAMPLE_HEARTBEAT,
            SAMPLE_NAS_LINE,
        ]
        events = parse_log_lines(lines)
        assert len(events) == 11
        types = [e.event_type for e in events]
        assert AmfEventType.REGISTRATION_REQUEST in types
        assert AmfEventType.AUTH_SUCCESS in types
        assert AmfEventType.REGISTRATION_COMPLETE in types
        assert AmfEventType.PDU_ACCEPT in types
        assert AmfEventType.CONTEXT_RELEASE_COMPLETE in types
        assert AmfEventType.GNB_STATUS in types
        assert AmfEventType.UE_TABLE_STATUS in types

    def test_timestamp_parsing(self):
        ev = parse_line(SAMPLE_REG_COMPLETE)
        assert ev.timestamp.year == 2026
        assert ev.timestamp.month == 5
        assert ev.timestamp.day == 13
        assert ev.timestamp.hour == 18
        assert ev.timestamp.minute == 42
        assert ev.timestamp.second == 20
