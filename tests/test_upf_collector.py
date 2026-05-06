"""Tests for UPF Prometheus scraper — parsing, diffing, and spike detection."""

import time
from pathlib import Path

from network_a.collector.upf_traffic_collector import (
    UpfSnapshot,
    collect_stub,
    detect_spike,
    diff_snapshots,
    parse_snapshots,
)


SAMPLE_METRICS = Path(__file__).resolve().parent.parent / "data" / "logs" / "sample_upf_metrics.txt"


class TestParseSnapshots:
    def test_parse_sample_metrics(self):
        text = SAMPLE_METRICS.read_text()
        snaps = parse_snapshots(text)
        assert len(snaps) == 2

        ips = {s.ue_ip for s in snaps}
        assert "12.1.1.2" in ips
        assert "12.1.1.3" in ips

    def test_parse_ue_with_traffic(self):
        text = SAMPLE_METRICS.read_text()
        snaps = parse_snapshots(text)
        main_ue = next(s for s in snaps if s.ue_ip == "12.1.1.2")
        assert main_ue.bytes_uplink == 1_500_000
        assert main_ue.bytes_downlink == 8_200_000
        assert main_ue.packets_uplink == 1200
        assert main_ue.packets_downlink == 5400
        assert main_ue.pfcp_session_active is True

    def test_parse_ue_with_minimal_traffic(self):
        text = SAMPLE_METRICS.read_text()
        snaps = parse_snapshots(text)
        small_ue = next(s for s in snaps if s.ue_ip == "12.1.1.3")
        assert small_ue.bytes_uplink == 220
        assert small_ue.bytes_downlink == 880
        assert small_ue.pfcp_session_active is True

    def test_parse_empty_metrics(self):
        snaps = parse_snapshots("")
        assert snaps == []

    def test_parse_comments_only(self):
        text = "# HELP something\n# TYPE something counter\n"
        snaps = parse_snapshots(text)
        assert snaps == []


class TestDiffSnapshots:
    def test_normal_growth(self):
        now = time.time()
        prev = UpfSnapshot(ts=now, ue_ip="12.1.1.2", bytes_uplink=1000, bytes_downlink=5000,
                           packets_uplink=10, packets_downlink=50, pfcp_session_active=True)
        curr = UpfSnapshot(ts=now + 5.0, ue_ip="12.1.1.2", bytes_uplink=2000, bytes_downlink=9000,
                           packets_uplink=20, packets_downlink=90, pfcp_session_active=True)
        d = diff_snapshots(prev, curr)
        assert d["bytes_uplink_delta"] == 1000
        assert d["bytes_downlink_delta"] == 4000
        assert d["packets_uplink_delta"] == 10
        assert d["counter_reset_detected"] is False
        assert d["throughput_uplink_kbps"] > 0

    def test_counter_reset(self):
        now = time.time()
        prev = UpfSnapshot(ts=now, ue_ip="12.1.1.2", bytes_uplink=5000, bytes_downlink=10000,
                           packets_uplink=50, packets_downlink=100, pfcp_session_active=True)
        curr = UpfSnapshot(ts=now + 5.0, ue_ip="12.1.1.2", bytes_uplink=100, bytes_downlink=200,
                           packets_uplink=2, packets_downlink=4, pfcp_session_active=True)
        d = diff_snapshots(prev, curr)
        assert d["counter_reset_detected"] is True
        assert d["bytes_uplink_delta"] == 100
        assert d["bytes_downlink_delta"] == 200


class TestSpikeDetection:
    def test_spike_detected(self):
        assert detect_spike(8000, 100) is True

    def test_no_spike_similar_rate(self):
        assert detect_spike(5000, 4000) is False

    def test_no_spike_below_floor(self):
        assert detect_spike(500, 10) is False


class TestCollectStub:
    def test_stub_returns_valid_snapshot(self):
        snap = collect_stub("208950000000031")
        assert snap.ue_ip == "12.1.1.2"
        assert snap.bytes_uplink > 0
        assert snap.pfcp_session_active is True
