"""
UPF traffic collector — Prometheus scraper.

OAI UPF exposes Prometheus metrics when enabled:
    register_nf:
      general:
        metrics:
          enabled: true
          port: 9090

Verify with: curl -s http://oai-upf:9090/metrics | grep -i bytes

Falls back to stub data when Prometheus is unreachable (development mode).
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

LABEL_KEY = "ue_ip"


@dataclass(frozen=True)
class UpfSnapshot:
    ts: float
    ue_ip: str
    bytes_uplink: int
    bytes_downlink: int
    packets_uplink: int
    packets_downlink: int
    pfcp_session_active: bool


@dataclass(frozen=True)
class SessionTraffic:
    """Per-session traffic derived from cumulative UPF counters.

    Unlike UpfSnapshot (which holds lifetime cumulative counters), these
    values are scoped to a single UE session: byte deltas since the session
    started, the peak throughput observed during it, and the number of
    throughput spikes detected.
    """

    bytes_uplink: int
    bytes_downlink: int
    peak_throughput_kbps: int
    spike_count: int


async def fetch_metrics(upf_url: str = "http://localhost:9090/metrics", timeout_s: float = 2.0) -> str:
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.get(upf_url)
    resp.raise_for_status()
    return resp.text


def parse_snapshots(metrics_text: str) -> list[UpfSnapshot]:
    by_ue: dict[str, dict] = {}
    ts = time.time()

    for line in metrics_text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            metric_part, value_str = line.rsplit(" ", 1)
            value = float(value_str)
        except ValueError:
            continue

        ue_ip = _extract_label(line, LABEL_KEY)
        if not ue_ip:
            continue

        entry = by_ue.setdefault(ue_ip, {
            "bytes_uplink": 0, "bytes_downlink": 0,
            "packets_uplink": 0, "packets_downlink": 0,
            "pfcp_session_active": False,
        })

        direction = _extract_label(line, "direction")

        if "upf_traffic_bytes_total" in metric_part:
            if direction == "uplink":
                entry["bytes_uplink"] = int(value)
            elif direction == "downlink":
                entry["bytes_downlink"] = int(value)
        elif "upf_traffic_packets_total" in metric_part:
            if direction == "uplink":
                entry["packets_uplink"] = int(value)
            elif direction == "downlink":
                entry["packets_downlink"] = int(value)
        elif "upf_pfcp_sessions_active" in metric_part:
            entry["pfcp_session_active"] = value > 0

    return [UpfSnapshot(ts=ts, ue_ip=ip, **v) for ip, v in by_ue.items()]


def diff_snapshots(prev: UpfSnapshot, curr: UpfSnapshot) -> dict:
    assert prev.ue_ip == curr.ue_ip
    interval_s = max(1e-3, curr.ts - prev.ts)

    def _delta(p: int, c: int) -> int:
        return c if c < p else c - p

    d_up = _delta(prev.bytes_uplink, curr.bytes_uplink)
    d_dn = _delta(prev.bytes_downlink, curr.bytes_downlink)

    return {
        "interval_s": interval_s,
        "bytes_uplink_delta": d_up,
        "bytes_downlink_delta": d_dn,
        "packets_uplink_delta": _delta(prev.packets_uplink, curr.packets_uplink),
        "packets_downlink_delta": _delta(prev.packets_downlink, curr.packets_downlink),
        "throughput_uplink_kbps": (d_up * 8 / 1000) / interval_s,
        "throughput_downlink_kbps": (d_dn * 8 / 1000) / interval_s,
        "counter_reset_detected": (
            curr.bytes_uplink < prev.bytes_uplink
            or curr.bytes_downlink < prev.bytes_downlink
        ),
    }


def detect_spike(throughput_kbps: float, recent_avg_kbps: float, threshold_multiplier: float = 3.0) -> bool:
    return throughput_kbps > 1000 and throughput_kbps > recent_avg_kbps * threshold_multiplier


def collect_stub(imsi: str) -> UpfSnapshot:
    return UpfSnapshot(
        ts=time.time(),
        ue_ip="12.1.1.2",
        bytes_uplink=1_500_000,
        bytes_downlink=12_000_000,
        packets_uplink=1200,
        packets_downlink=5400,
        pfcp_session_active=True,
    )


def _extract_label(line: str, key: str) -> str | None:
    m = re.search(rf'{key}="([^"]*)"', line)
    return m.group(1) if m else None


def _aggregate(snapshots: list[UpfSnapshot]) -> UpfSnapshot:
    """Collapse all reported UEs into one cumulative snapshot.

    Under the single-UE testbed assumption there is normally exactly one
    entry; summing is a safe fallback if the UPF briefly reports a stale or
    second IP at the same time.
    """
    return UpfSnapshot(
        ts=snapshots[0].ts,
        ue_ip=snapshots[0].ue_ip,
        bytes_uplink=sum(s.bytes_uplink for s in snapshots),
        bytes_downlink=sum(s.bytes_downlink for s in snapshots),
        packets_uplink=sum(s.packets_uplink for s in snapshots),
        packets_downlink=sum(s.packets_downlink for s in snapshots),
        pfcp_session_active=any(s.pfcp_session_active for s in snapshots),
    )


class UpfMonitor:
    """Single-UE UPF traffic monitor.

    Assumes at most one active UE on the testbed at a time (one USRP B210).
    Ingests cumulative UPF counters from each scrape and derives per-session
    traffic by diffing against a baseline captured at session start. Peak
    throughput and spike counts are accumulated only while a session is open.

    NOTE: with concurrent UEs the per-session attribution is approximate —
    traffic from all active UEs is aggregated together. This is acceptable for
    the single-UE testbed; multi-UE scale tests need IMSI<->IP correlation.
    """

    def __init__(self, spike_window: int = 6) -> None:
        self._latest: UpfSnapshot | None = None
        self._prev: UpfSnapshot | None = None
        self._recent_kbps: deque[float] = deque(maxlen=spike_window)
        self._session_base: UpfSnapshot | None = None
        self._session_peak_kbps: float = 0.0
        self._session_spikes: int = 0
        self._in_session: bool = False

    def update(self, snapshots: list[UpfSnapshot]) -> None:
        """Ingest one scrape of UPF metrics."""
        if not snapshots:
            return
        curr = _aggregate(snapshots)
        if self._prev is not None:
            d = diff_snapshots(self._prev, curr)
            tput = d["throughput_uplink_kbps"] + d["throughput_downlink_kbps"]
            avg = (
                sum(self._recent_kbps) / len(self._recent_kbps)
                if self._recent_kbps
                else 0.0
            )
            if self._in_session:
                if detect_spike(tput, avg):
                    self._session_spikes += 1
                self._session_peak_kbps = max(self._session_peak_kbps, tput)
            self._recent_kbps.append(tput)
        self._prev = curr
        self._latest = curr

    def start_session(self) -> None:
        """Mark the start of a UE session — captures the byte baseline."""
        self._session_base = self._latest
        self._session_peak_kbps = 0.0
        self._session_spikes = 0
        self._in_session = True

    def finalize_session(self) -> SessionTraffic:
        """Return traffic accumulated since the last start_session()."""
        self._in_session = False
        if self._latest is None:
            return SessionTraffic(0, 0, 0, 0)
        base = self._session_base
        if base is None:
            up, dn = self._latest.bytes_uplink, self._latest.bytes_downlink
        else:
            up = max(0, self._latest.bytes_uplink - base.bytes_uplink)
            dn = max(0, self._latest.bytes_downlink - base.bytes_downlink)
        return SessionTraffic(
            bytes_uplink=up,
            bytes_downlink=dn,
            peak_throughput_kbps=int(self._session_peak_kbps),
            spike_count=self._session_spikes,
        )
