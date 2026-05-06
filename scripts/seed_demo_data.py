"""
Seed the Postgres database with demo UE session data for live server demo.

Usage:
    python -m scripts.seed_demo_data

Requires Postgres running (via docker-compose) OR uses in-memory fallback.
Creates 3 UEs with varying behavioural profiles for demonstration.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from network_a import db


DEMO_UES = [
    {
        "pseudonym": "UE_HASH_001",
        "imsi_hmac": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "profile": "normal",
        "sessions": 10,
        "auth_failure_rate": 0.0,
        "pdu_failure_rate": 0.0,
        "spike_rate": 0.0,
        "risk_flags": [],
    },
    {
        "pseudonym": "UE_HASH_002",
        "imsi_hmac": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
        "profile": "suspicious",
        "sessions": 8,
        "auth_failure_rate": 0.15,
        "pdu_failure_rate": 0.10,
        "spike_rate": 0.25,
        "risk_flags": [{"flag_type": "auth_burst", "severity": "medium"}],
    },
    {
        "pseudonym": "UE_HASH_003",
        "imsi_hmac": "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "profile": "anomalous",
        "sessions": 5,
        "auth_failure_rate": 0.60,
        "pdu_failure_rate": 0.50,
        "spike_rate": 0.80,
        "risk_flags": [
            {"flag_type": "auth_anomaly", "severity": "high"},
            {"flag_type": "traffic_flood", "severity": "critical"},
        ],
    },
]


async def seed():
    await db.init_pool()

    for ue in DEMO_UES:
        print(f"Seeding {ue['pseudonym']} ({ue['profile']})...")

        await db.insert_identity(ue["pseudonym"], ue["imsi_hmac"], "Network_B")

        base_time = datetime.now(timezone.utc) - timedelta(hours=ue["sessions"])

        for i in range(ue["sessions"]):
            auth_attempts = 5
            auth_failures = int(auth_attempts * ue["auth_failure_rate"])
            pdu_attempts = 3
            pdu_failures = int(pdu_attempts * ue["pdu_failure_rate"])
            spike_count = 1 if (i / ue["sessions"]) < ue["spike_rate"] else 0

            await db.insert_session(
                pseudonym=ue["pseudonym"],
                started_at=base_time + timedelta(hours=i),
                ended_at=base_time + timedelta(hours=i, minutes=30),
                duration_sec=1800,
                registration_success=True,
                auth_attempts=auth_attempts,
                auth_failures=auth_failures,
                pdu_attempts=pdu_attempts,
                pdu_failures=pdu_failures,
                spike_count=spike_count,
                requested_slice="eMBB",
                requested_dnn="internet",
                bytes_uplink=5000 + i * 1000,
                bytes_downlink=20000 + i * 3000,
                peak_throughput_kbps=100 + i * 50,
            )

        for flag in ue["risk_flags"]:
            await db.insert_risk_flag(
                ue["pseudonym"],
                flag["flag_type"],
                flag["severity"],
                {"source": "demo_seed"},
            )

    await db.close_pool()
    print(f"\nSeeded {len(DEMO_UES)} UEs with session data.")


def main():
    asyncio.run(seed())


if __name__ == "__main__":
    main()
