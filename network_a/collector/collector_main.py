"""
Long-running collector service: tails AMF logs, scrapes UPF Prometheus,
and writes session records to Postgres.

Usage:
    python3 -m network_a.collector.collector_main [--amf-log PATH] [--upf-url URL]
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import os
import time
from pathlib import Path

from network_a import db
from network_a.collector.amf_log_parser import AmfEventType, parse_line
from network_a.collector.feature_extractor import build_session_record, persist_session
from network_a.collector.upf_traffic_collector import collect_stub, fetch_metrics, parse_snapshots
from network_a.identity.identity_mapper import get_or_create_pseudonym

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

DEFAULT_AMF_LOG = "data/logs/amf_live.log"
DEFAULT_UPF_URL = "http://localhost:9090/metrics"
SCRAPE_INTERVAL = 10


async def tail_file(path: Path) -> None:
    """Tail a log file like `tail -F`, yielding new lines."""
    logger.info("Tailing AMF log: %s", path)

    if not path.exists():
        logger.warning("AMF log not found: %s — waiting for it to appear", path)
        while not path.exists():
            await asyncio.sleep(2)

    session_events: dict[str, list] = {}
    # Track the "current" IMSI across consecutive log lines.
    # Many OAI AMF events (Context Release, Security Mode Complete, etc.)
    # don't include the IMSI in the log line itself — they rely on being
    # part of a sequential procedure for a single UE.  We propagate the
    # most-recently-seen IMSI to those events so they aren't dropped.
    current_imsi: str | None = None

    with open(path) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)

                for imsi, events in list(session_events.items()):
                    has_release = any(
                        e.event_type in (AmfEventType.CONTEXT_RELEASE_REQUEST, AmfEventType.CONTEXT_RELEASE_COMPLETE)
                        for e in events
                    )
                    if has_release and len(events) >= 2:
                        pseudonym = await get_or_create_pseudonym(imsi)
                        record = build_session_record(pseudonym, events)
                        session_id = await persist_session(record)
                        logger.info("Session %s persisted for %s (IMSI %s)", session_id, pseudonym, imsi)
                        del session_events[imsi]
                continue

            event = parse_line(line)
            if event is None:
                continue

            # Skip periodic gNB status lines — not session events
            if event.event_type == AmfEventType.GNB_STATUS:
                continue

            # Update IMSI tracking from any event that carries an inline IMSI
            if event.imsi:
                current_imsi = event.imsi

            # Resolve IMSI: prefer inline, fall back to tracked context
            imsi = event.imsi or current_imsi
            if not imsi:
                logger.debug("Skipping %s — no IMSI context yet", event.event_type.value)
                continue

            # UE table status is useful for IMSI tracking but is a periodic
            # status dump, not a session lifecycle event — don't add to session
            if event.event_type == AmfEventType.UE_TABLE_STATUS:
                continue

            logger.info("Event: %s for IMSI %s", event.event_type.value, imsi)
            session_events.setdefault(imsi, []).append(event)


async def scrape_upf_loop(upf_url: str) -> None:
    """Periodically scrape UPF Prometheus metrics."""
    logger.info("UPF scraper started (url=%s, interval=%ds)", upf_url, SCRAPE_INTERVAL)
    while True:
        try:
            text = fetch_metrics(upf_url)
            snapshots = parse_snapshots(text)
            logger.info("UPF scrape: %d UEs active", len(snapshots))
        except Exception as e:
            logger.debug("UPF scrape failed: %s (will retry)", e)
        await asyncio.sleep(SCRAPE_INTERVAL)


async def main(amf_log: str, upf_url: str) -> None:
    await db.init_pool()
    try:
        tasks = [
            asyncio.create_task(tail_file(Path(amf_log))),
            asyncio.create_task(scrape_upf_loop(upf_url)),
        ]
        await asyncio.gather(*tasks)
    finally:
        await db.close_pool()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IBN-ZTA Behaviour Collector")
    parser.add_argument("--amf-log", default=os.environ.get("AMF_LOG_PATH", DEFAULT_AMF_LOG))
    parser.add_argument("--upf-url", default=os.environ.get("UPF_PROMETHEUS_URL", DEFAULT_UPF_URL))
    args = parser.parse_args()
    asyncio.run(main(args.amf_log, args.upf_url))
