"""
Network A FastAPI application.

When running with the in-memory DB fallback (no Postgres), the collector
is embedded as a background asyncio task inside the same process so that
both the API routes and the collector share the same ``_MEMORY_STORE``.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from network_a import db
from network_a.api.routes import router

logger = logging.getLogger(__name__)

_DEFAULT_AMF_LOG = "data/logs/amf_live.log"
_DEFAULT_UPF_URL = "http://localhost:9090/metrics"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()

    background_tasks: list[asyncio.Task] = []

    # When using in-memory fallback, run the collector inside this process
    # so that persisted sessions are visible to the API routes.
    if db._USE_MEMORY_FALLBACK:
        from network_a.collector.collector_main import tail_file, scrape_upf_loop

        amf_log = os.environ.get("AMF_LOG_PATH", _DEFAULT_AMF_LOG)
        upf_url = os.environ.get("UPF_PROMETHEUS_URL", _DEFAULT_UPF_URL)

        logger.info(
            "In-memory mode: starting embedded collector (amf=%s, upf=%s)",
            amf_log, upf_url,
        )
        background_tasks.append(asyncio.create_task(tail_file(Path(amf_log))))
        background_tasks.append(asyncio.create_task(scrape_upf_loop(upf_url)))

    yield

    for t in background_tasks:
        t.cancel()
    await db.close_pool()


app = FastAPI(
    title="Network A — Summary Provider",
    version="0.2.0",
    description="Privacy-preserving UE behavioural summary API",
    lifespan=lifespan,
)
app.include_router(router, prefix="/v1")
