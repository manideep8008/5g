"""Network B attachment watcher.

Tails Network B's AMF log (its own OAI CN5G instance) and auto-triggers
an access decision on every fresh REGISTRATION_COMPLETE. Without this,
Network B is reactive only — it waits for someone to call the access
API manually. With it, the ZTA flow fires automatically the moment the
UE attaches to Network B's gNB.

Usage:
    python3 -m network_b.collector.attachment_watcher \\
        [--amf-log PATH] [--network-b-url URL]

Env vars:
    AMF_LOG_PATH         Path to Network B's AMF log file
    NETWORK_B_URL        Base URL of Network B decision API (default :8002)
    REQUESTED_SLICE      Slice to request for auto-triggered decisions
    REQUESTED_DNN        DNN to request
    REQUESTED_SERVICE    Service to request
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from network_b.contract.amf_log_parser import AmfEventType, parse_line
from network_b.contract.identity import pseudonymise_imsi

logger = logging.getLogger(__name__)

DEFAULT_AMF_LOG = "data/logs/netb-amf.log"
DEFAULT_NETWORK_B_URL = "http://localhost:8002"
DEFAULT_SLICE = "eMBB"
DEFAULT_DNN = "internet"
DEFAULT_SERVICE = "standard_data"
HTTP_TIMEOUT_SEC = 15.0


async def trigger_access_decision(
    imsi: str,
    network_b_url: str,
    requested_slice: str,
    requested_dnn: str,
    requested_service: str,
    client: httpx.AsyncClient | None = None,
) -> dict | None:
    pseudonym = pseudonymise_imsi(imsi)
    payload = {
        "request_id": str(uuid.uuid4()),
        "ue_pseudonym": pseudonym,
        "requested_network": "Network_B",
        "requested_slice": requested_slice,
        "requested_dnn": requested_dnn,
        "requested_service": requested_service,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC)
    try:
        resp = await client.post(f"{network_b_url}/v1/access/request", json=payload)
        if resp.status_code != 200:
            logger.warning(
                "Decision API returned %d for %s: %s",
                resp.status_code, pseudonym, resp.text,
            )
            return None
        decision = resp.json()
        logger.info(
            "UE %s attached → tier=%s risk=%.2f reason=%s",
            pseudonym,
            decision.get("final_tier"),
            decision.get("risk_score", 0.0),
            decision.get("reason"),
        )
        return decision
    except httpx.HTTPError as exc:
        logger.error("Failed to call decision API for %s: %s", pseudonym, exc)
        return None
    finally:
        if owns_client:
            await client.aclose()


async def watch_attachments(
    amf_log_path: Path,
    network_b_url: str,
    requested_slice: str = DEFAULT_SLICE,
    requested_dnn: str = DEFAULT_DNN,
    requested_service: str = DEFAULT_SERVICE,
) -> None:
    logger.info("Watching Network B AMF log: %s", amf_log_path)
    logger.info("Decision API: %s", network_b_url)

    while not amf_log_path.exists():
        logger.warning("AMF log not found yet, waiting: %s", amf_log_path)
        await asyncio.sleep(2)

    current_imsi: str | None = None
    in_flight: set[str] = set()

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SEC) as client:
        with open(amf_log_path) as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.5)
                    continue

                event = parse_line(line)
                if event is None:
                    continue
                if event.event_type == AmfEventType.GNB_STATUS:
                    continue
                if event.imsi:
                    current_imsi = event.imsi
                imsi = event.imsi or current_imsi
                if not imsi:
                    continue

                if event.event_type == AmfEventType.REGISTRATION_COMPLETE:
                    if imsi in in_flight:
                        continue
                    in_flight.add(imsi)
                    logger.info(
                        "REGISTRATION_COMPLETE imsi=%s → triggering ZTA decision",
                        imsi,
                    )
                    asyncio.create_task(
                        _dispatch_and_release(
                            imsi, network_b_url, requested_slice,
                            requested_dnn, requested_service, client, in_flight,
                        )
                    )
                elif event.event_type in (
                    AmfEventType.CONTEXT_RELEASE_REQUEST,
                    AmfEventType.CONTEXT_RELEASE_COMPLETE,
                ):
                    in_flight.discard(imsi)


async def _dispatch_and_release(
    imsi: str,
    network_b_url: str,
    requested_slice: str,
    requested_dnn: str,
    requested_service: str,
    client: httpx.AsyncClient,
    in_flight: set[str],
) -> None:
    try:
        await trigger_access_decision(
            imsi=imsi,
            network_b_url=network_b_url,
            requested_slice=requested_slice,
            requested_dnn=requested_dnn,
            requested_service=requested_service,
            client=client,
        )
    finally:
        # Keep in_flight until CONTEXT_RELEASE so we don't re-trigger on
        # duplicate REGISTRATION_COMPLETE lines that some AMF builds emit.
        pass


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Network B attachment watcher")
    parser.add_argument(
        "--amf-log",
        default=os.environ.get("AMF_LOG_PATH", DEFAULT_AMF_LOG),
    )
    parser.add_argument(
        "--network-b-url",
        default=os.environ.get("NETWORK_B_URL", DEFAULT_NETWORK_B_URL),
    )
    parser.add_argument(
        "--slice",
        default=os.environ.get("REQUESTED_SLICE", DEFAULT_SLICE),
    )
    parser.add_argument(
        "--dnn",
        default=os.environ.get("REQUESTED_DNN", DEFAULT_DNN),
    )
    parser.add_argument(
        "--service",
        default=os.environ.get("REQUESTED_SERVICE", DEFAULT_SERVICE),
    )
    return parser


async def _main() -> None:
    args = _build_arg_parser().parse_args()
    await watch_attachments(
        amf_log_path=Path(args.amf_log),
        network_b_url=args.network_b_url,
        requested_slice=args.slice,
        requested_dnn=args.dnn,
        requested_service=args.service,
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    asyncio.run(_main())
