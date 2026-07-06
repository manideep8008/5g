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
    bytes_uplink: int
    bytes_downlink: int
    peak_throughput_kbps: int
    spike_count: int

#fetch the metrics from the UPF
async def fetch_metrics(upf_url: str = "http://localhost:9090/metrics", timeout_s: float = 2.0) -> str:
    #get the metrics from the UPF
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.get(upf_url)
    #raise an exception if the request was not successful
    resp.raise_for_status()
    return resp.text

#parse UPF metrics into a list of UpfSnapshot objects
def parse_snapshots(metrics_text: str) -> list[UpfSnapshot]:
    #create a dictionary to store the metrics
    by_ue: dict[str, dict] = {}
    ts = time.time()

    #parse each line in the metrics text and extract the metrics for each UE
    #each line in the metrics text is in the format "metric{label="value"} value"
    #for example: "upf_traffic_bytes_total{direction="uplink",ue_ip="12.1.1.2"} 1000"
    for line in metrics_text.strip().split("\n"):
        line = line.strip()
        #skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        #try to parse the metrics
        try:
            #split the line into the metric part and the value part
            metric_part, value_str = line.rsplit(" ", 1)
            value = float(value_str)
        except ValueError:
            #skip lines that cannot be parsed
            continue

        #extract the UE IP address from the line
        ue_ip = _extract_label(line, LABEL_KEY)
        if not ue_ip:
            #skip lines that do not have a UE IP address
            continue

        #create a dictionary to store the metrics
        entry = by_ue.setdefault(ue_ip, {
            "bytes_uplink": 0, "bytes_downlink": 0,
            "packets_uplink": 0, "packets_downlink": 0,
            "pfcp_session_active": False,
        })

        #extract the direction from the line
        direction = _extract_label(line, "direction")

        #check the metric type and extract the value
        if "upf_traffic_bytes_total" in metric_part:
            #extract the bytes_uplink and bytes_downlink from the line
            if direction == "uplink":
                entry["bytes_uplink"] = int(value)
            elif direction == "downlink":
                entry["bytes_downlink"] = int(value)
        elif "upf_traffic_packets_total" in metric_part:
            #extract the packets_uplink and packets_downlink from the line
            if direction == "uplink":
                entry["packets_uplink"] = int(value)
            elif direction == "downlink":
                entry["packets_downlink"] = int(value)
        elif "upf_pfcp_sessions_active" in metric_part:
            entry["pfcp_session_active"] = value > 0

    #create a list of UpfSnapshot objects from the dictionary
    return [UpfSnapshot(ts=ts, ue_ip=ip, **v) for ip, v in by_ue.items()]

#calculate the difference between two snapshots
def diff_snapshots(prev: UpfSnapshot, curr: UpfSnapshot) -> dict:
    #assert that the UE IPs are the same
    assert prev.ue_ip == curr.ue_ip
    #calculate the interval in seconds (1 ms minimum to avoid division by zero)
    interval_s = max(1e-3, curr.ts - prev.ts)

    #_delta calculates the difference between two counter values (previous and current).
    #handle counter resets
    def _delta(p: int, c: int) -> int:
        #return the difference between the current and previous values
        #handle counter resets
        return c if c < p else c - p

    #calculate the delta between the previous and current values
    d_up = _delta(prev.bytes_uplink, curr.bytes_uplink)
    d_dn = _delta(prev.bytes_downlink, curr.bytes_downlink)

    #calculate the throughput in kbps
    #convert the delta to bits per second
    #kbps = (delta * 8 / 1000) / interval_s
    throughput_uplink_kbps = (d_up * 8 / 1000) / interval_s
    throughput_downlink_kbps = (d_dn * 8 / 1000) / interval_s
    #calculate the packets per second
    #packets_per_second = delta / interval_s
    packets_uplink_delta = _delta(prev.packets_uplink, curr.packets_uplink)
    packets_downlink_delta = _delta(prev.packets_downlink, curr.packets_downlink)

# example
# prev= UpfSnapshot(
#     ts=100.0,
#     ue_ip="10.0.0.1",
#     bytes_uplink=1000,
#     bytes_downlink=2000,
#     packets_uplink=10,
#     packets_downlink=20,
#     pfcp_session_active=True
# )

# curr = UpfSnapshot(
#     ts=105.0,
#     ue_ip="10.0.0.1",
#     bytes_uplink=1500,
#     bytes_downlink=3000,
#     packets_uplink=15,
#     packets_downlink=30,
#     pfcp_session_active=True
# )

# diff = {
#     "interval_s": 5.0,
#     "bytes_uplink_delta": 500,
#     "bytes_downlink_delta": 1000,
#     "packets_uplink_delta": 5,
#     "packets_downlink_delta": 10,
#     "throughput_uplink_kbps": 0.8,
#     "throughput_downlink_kbps": 1.6,
#     " counter_reset_detected": False
# }

    #return the differences
    return {
        "interval_s": interval_s,
        "bytes_uplink_delta": d_up,
        "bytes_downlink_delta": d_dn,
        "packets_uplink_delta": packets_uplink_delta,
        "packets_downlink_delta": packets_downlink_delta,
        "throughput_uplink_kbps": throughput_uplink_kbps,
        "throughput_downlink_kbps": throughput_downlink_kbps,
        #check if the counters have been reset
        "counter_reset_detected": (
            curr.bytes_uplink < prev.bytes_uplink
            or curr.bytes_downlink < prev.bytes_downlink
        ),
    }


#detect spikes
def detect_spike(throughput_kbps: float, recent_avg_kbps: float, threshold_multiplier: float = 3.0, spike_threshold_kbps: float = 1000.0) -> bool:
    """Detect a spike in throughput.
    
    Args:
        throughput_kbps: The current throughput in kbps.
        recent_avg_kbps: The recent average throughput in kbps.
        threshold_multiplier: The threshold multiplier.
        spike_threshold_kbps: The spike threshold in kbps (default: 1000) for low kbps values.
    
    Returns:
        True if the throughput is greater than the maximum of the spike threshold and the average throughput multiplied by the threshold multiplier, False otherwise.
    """

    #A spike is defined as throughput greater than the maximum of the spike threshold and the average throughput multiplied by the threshold multiplier
    #Example 1:
    #if throughput_kbps = 2000, recent_avg_kbps = 100, threshold_multiplier = 3, spike_threshold_kbps = 1000
    #then max(spike_threshold_kbps, recent_avg_kbps * threshold_multiplier) = max(1000, 100 * 3) = max(1000, 300) = 1000
    #throughput_kbps = 2000 > 1000, thus it is a spike
    
    #Example 2:
    #if throughput_kbps = 200, recent_avg_kbps = 50, threshold_multiplier = 3, spike_threshold_kbps = 1000
    #then max(spike_threshold_kbps, recent_avg_kbps * threshold_multiplier) = max(1000, 50 * 3) = max(1000, 150) = 1000
    #throughput_kbps = 200 < 1000, thus it is not a spike

    #the logic is that if the current throughput is greater than the maximum of the spike threshold and the average throughput multiplied by the threshold multiplier, then it is a spike
    return throughput_kbps > max(spike_threshold_kbps, recent_avg_kbps * threshold_multiplier)


def collect_stub(imsi: str) -> UpfSnapshot:
    #create a stub snapshot with example values
    #ts: the timestamp of the snapshot
    #ue_ip: the IP address of the UE
    #bytes_uplink: the total number of bytes sent from the UE to the network
    #bytes_downlink: the total number of bytes sent from the network to the UE
    #packets_uplink: the total number of packets sent from the UE to the network
    #packets_downlink: the total number of packets sent from the network to the UE
    #pfcp_session_active: whether the PFCP session is active
    #example values
    #bytes_uplink: 1.5 MB
    #bytes_downlink: 12 MB
    #packets_uplink: 1200
    #packets_downlink: 5400
    
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






#The UpfMonitor class is a stateful monitor designed to ingest continuous streams of Prometheus snapshots for a User Equipment (UE). 
#It handles baseline traffic aggregation, tracks throughput trends to detect network activity spikes, 
#and accumulates session-level metrics (total volume, peak throughput, and spike counts).
class UpfMonitor:
    #initializes the monitor with a spike window
    def __init__(self, spike_window: int = 6) -> None:
        #latest snapshot
        self._latest: UpfSnapshot | None = None
        #previous snapshot
        self._prev: UpfSnapshot | None = None
        #recent throughput history
        self._recent_kbps: deque[float] = deque(maxlen=spike_window)
        #session base
        self._session_base: UpfSnapshot | None = None
        #session peak throughput
        self._session_peak_kbps: float = 0.0
        #session spikes
        self._session_spikes: int = 0
        #in session flag
        self._in_session: bool = False

    #update method
    #gets a list of snapshots from the prometheus scrapper
    def update(self, snapshots: list[UpfSnapshot]) -> None:
        #if no snapshots are provided, return
        if not snapshots:
            return
        #aggregate snapshots if more than one is provided, which should not happen in the single-UE testbed.
        curr = _aggregate(snapshots)
       
        #if previous snapshot is not None, calculate the differences
        if self._prev is not None:
            #calculate the differences
            d = diff_snapshots(self._prev, curr)
            
            #calculate the total throughput
            #This is the total throughput over the last interval.
            #Example:
            #if d = {"throughput_uplink_kbps": 10, "throughput_downlink_kbps": 20}, then tput = 30
            tput = d["throughput_uplink_kbps"] + d["throughput_downlink_kbps"]

            #calculate the average throughput
            #This is the average throughput over the last spike_window intervals.
            #If _recent_kbps is empty, the average throughput is 0.0.
            #Example:
            #if _recent_kbps = [10, 20, 30], then sum(self._recent_kbps) = 60, len(self._recent_kbps) = 3, avg = 20
            #if _recent_kbps = [], then sum(self._recent_kbps) = 0, len(self._recent_kbps) = 0, avg = 0.0
            avg = (
                sum(self._recent_kbps) / len(self._recent_kbps)
                if self._recent_kbps
                else 0.0
            )
            #check if the monitor is in a session
            if self._in_session:
                #detect spikes
                #if the throughput is greater than the maximum of the spike threshold and the average throughput multiplied by the threshold multiplier, then it is a spike
                #Example:
                #if tput = 30, avg = 20, spike_threshold_kbps = 1000, threshold_multiplier = 3
                #then max(1000, 20 * 3) = max(1000, 60) = 1000
                #tput = 30 < 1000, thus it is not a spike
                if detect_spike(tput, avg):
                    self._session_spikes += 1
                #update peak throughput
                #This is the peak throughput over the last spike_window intervals.
                #Example:
                #if self._session_peak_kbps = 10, tput = 20
                #then self._session_peak_kbps = max(10, 20) = 20
                self._session_peak_kbps = max(self._session_peak_kbps, tput)
            #add throughput to recent history
            #This is the recent throughput history over the last spike_window intervals.
            #Example:
            #if self._recent_kbps = [10, 20, 30], then self._recent_kbps = [20, 30, 40]
            self._recent_kbps.append(tput)
            
        #update previous and latest snapshots
        #This is the previous snapshot.
        self._prev = curr   
        #This is the latest snapshot.
        self._latest = curr

    #start a session
    #captures the byte baseline
    def start_session(self) -> None:
        #set the session base to the latest snapshot
        self._session_base = self._latest
        #reset peak throughput and spikes
        self._session_peak_kbps = 0.0
        self._session_spikes = 0
        #set in session flag
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
