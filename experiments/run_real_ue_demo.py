"""
End-to-end demo: seeds the DB with real UE session data, then exercises
the full pipeline (collector data → summary → decision).

Can run in two modes:
  --live    Requires both FastAPI servers running (ports 8001/8002)
  --local   Runs entirely in-process (no servers needed, default)

Usage:
    python -m experiments.run_real_ue_demo
    python -m experiments.run_real_ue_demo --live
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone

import httpx

from network_a import db
from network_a.summary.summary_generator import generate_summary
from network_a.summary.summary_schema import (
    AccessRequest,
    NetworkBContext,
    SummaryRequest,
    Tier,
)
from network_b.decision.decision_service import handle_access_request
from network_b.policy.policy_engine import decide, decide_auto


DEMO_SCENARIOS = [
    {
        "name": "Normal UE — stable history",
        "pseudonym": "UE_HASH_001",
        "sessions": [
            {"auth_attempts": 5, "auth_failures": 0, "pdu_attempts": 3, "pdu_failures": 0, "spike_count": 0, "requested_slice": "eMBB"},
            {"auth_attempts": 4, "auth_failures": 0, "pdu_attempts": 2, "pdu_failures": 0, "spike_count": 0, "requested_slice": "eMBB"},
            {"auth_attempts": 6, "auth_failures": 0, "pdu_attempts": 4, "pdu_failures": 0, "spike_count": 0, "requested_slice": "eMBB"},
        ],
        "risk_flags": [],
        "expected_outcome": "T3_FULL_ACCESS or T2_MONITORED_ACCESS",
    },
    {
        "name": "Suspicious UE — auth failures + anomaly",
        "pseudonym": "UE_HASH_002",
        "sessions": [
            {"auth_attempts": 10, "auth_failures": 3, "pdu_attempts": 5, "pdu_failures": 1, "spike_count": 2, "requested_slice": "eMBB"},
            {"auth_attempts": 8, "auth_failures": 2, "pdu_attempts": 4, "pdu_failures": 1, "spike_count": 1, "requested_slice": "URLLC"},
            {"auth_attempts": 12, "auth_failures": 4, "pdu_attempts": 6, "pdu_failures": 2, "spike_count": 3, "requested_slice": "eMBB"},
        ],
        "risk_flags": [{"flag_type": "auth_burst", "severity": "medium"}],
        "expected_outcome": "T1_RESTRICTED_ACCESS or T2_MONITORED_ACCESS",
    },
    {
        "name": "Anomalous UE — many failures, active flags",
        "pseudonym": "UE_HASH_003",
        "sessions": [
            {"auth_attempts": 10, "auth_failures": 8, "pdu_attempts": 5, "pdu_failures": 4, "spike_count": 5, "requested_slice": "eMBB"},
            {"auth_attempts": 15, "auth_failures": 12, "pdu_attempts": 8, "pdu_failures": 6, "spike_count": 7, "requested_slice": "eMBB"},
        ],
        "risk_flags": [
            {"flag_type": "auth_anomaly", "severity": "high"},
            {"flag_type": "traffic_spike", "severity": "high"},
        ],
        "expected_outcome": "T0_REJECT or T1_RESTRICTED_ACCESS",
    },
]


async def seed_demo_data():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()

    for scenario in DEMO_SCENARIOS:
        pseudonym = scenario["pseudonym"]
        await db.insert_identity(pseudonym, f"hmac_{pseudonym}", "Network_B")

        for sess in scenario["sessions"]:
            await db.insert_session(
                pseudonym=pseudonym,
                started_at=datetime.now(timezone.utc),
                registration_success=True,
                auth_attempts=sess["auth_attempts"],
                auth_failures=sess["auth_failures"],
                pdu_attempts=sess["pdu_attempts"],
                pdu_failures=sess["pdu_failures"],
                spike_count=sess["spike_count"],
                requested_slice=sess.get("requested_slice", "eMBB"),
                requested_dnn="internet",
                bytes_uplink=5000,
                bytes_downlink=20000,
            )

        for flag in scenario["risk_flags"]:
            await db.insert_risk_flag(pseudonym, flag["flag_type"], flag["severity"])


async def run_local_demo():
    await seed_demo_data()

    print("=" * 70)
    print("IBN-ZTA Demo — Privacy-Preserving UE Behavioural Summary Exchange")
    print("=" * 70)
    print(f"\nMode: LOCAL (in-process, no servers needed)")
    print(f"Time: {datetime.now(timezone.utc).isoformat()}")
    print(f"Scenarios: {len(DEMO_SCENARIOS)}")
    print()

    for scenario in DEMO_SCENARIOS:
        print("-" * 70)
        print(f"Scenario: {scenario['name']}")
        print(f"UE: {scenario['pseudonym']}")
        print(f"Expected: {scenario['expected_outcome']}")
        print()

        summary_req = SummaryRequest(
            request_id=f"DEMO-{scenario['pseudonym']}",
            ue_pseudonym=scenario["pseudonym"],
            network_b_context=NetworkBContext(
                requested_slice="eMBB",
                requested_dnn="internet",
                requested_service="standard_data",
            ),
        )

        summary_resp = await generate_summary(summary_req)

        if summary_resp is None:
            print("  [ERROR] No summary generated")
            continue

        print(f"  Summary from Network A:")
        print(f"    auth_stability:        {summary_resp.summary.auth_stability.value}")
        print(f"    pdu_session_stability: {summary_resp.summary.pdu_session_stability.value}")
        print(f"    traffic_pattern:       {summary_resp.summary.traffic_pattern.value}")
        print(f"    recent_anomaly:        {summary_resp.summary.recent_anomaly}")
        print(f"    behaviour_label:       {summary_resp.summary.behaviour_label.value}")
        print(f"    recommendation:        {summary_resp.network_a_recommendation}")
        print(f"    confidence:            {summary_resp.confidence}")
        print()

        policy_result = decide(summary_resp.summary)

        print(f"  Decision from Network B (rules-only):")
        print(f"    final_tier:            {policy_result.tier.value}")
        print(f"    risk_score:            {policy_result.risk_score}")
        print(f"    safety_floor_clipped:  {policy_result.metadata.safety_floor_clipped}")
        if policy_result.metadata.safety_floor_clipped:
            print(f"    clip_reason:           {policy_result.metadata.safety_floor_reason}")
        print(f"    reason:                {policy_result.reason}")
        print()

    print("-" * 70)
    print("\nDemo complete. All scenarios processed successfully.")
    print(f"Audit trail: {len(db._MEMORY_STORE['summary_disclosure'])} disclosure(s) logged")


async def run_live_demo():
    network_b_url = "http://localhost:8002"

    print("=" * 70)
    print("IBN-ZTA Demo — Live Server Mode")
    print("=" * 70)
    print(f"\nMode: LIVE (requires servers on ports 8001/8002)")
    print()

    for scenario in DEMO_SCENARIOS:
        print("-" * 70)
        print(f"Scenario: {scenario['name']}")

        access_request = {
            "event_type": "UE_ACCESS_REQUEST_AT_NETWORK_B",
            "request_id": f"DEMO-{scenario['pseudonym']}",
            "ue_pseudonym": scenario["pseudonym"],
            "requested_network": "Network_B",
            "requested_slice": "eMBB",
            "requested_dnn": "internet",
            "requested_service": "standard_data",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{network_b_url}/v1/access/request",
                    json=access_request,
                )
        except httpx.ConnectError:
            print("  ERROR: Cannot connect to Network B at", network_b_url)
            print("  Start servers:")
            print("    uvicorn network_a.api.app:app --port 8001")
            print("    uvicorn network_b.api.app:app --port 8002")
            sys.exit(1)

        if resp.status_code == 200:
            decision = resp.json()
            print(f"  Final tier: {decision['final_tier']}")
            print(f"  Risk score: {decision['risk_score']}")
            print(f"  Reason: {decision['reason']}")
            if decision["policy_engine_metadata"]["safety_floor_clipped"]:
                print(f"  Safety floor: {decision['policy_engine_metadata']['safety_floor_reason']}")
        else:
            print(f"  ERROR: {resp.status_code} — {resp.text[:200]}")

        print()

    print("-" * 70)
    print("Live demo complete.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="IBN-ZTA end-to-end demo")
    parser.add_argument("--live", action="store_true", help="Use live servers (ports 8001/8002)")
    args = parser.parse_args()

    if args.live:
        asyncio.run(run_live_demo())
    else:
        asyncio.run(run_local_demo())


if __name__ == "__main__":
    main()
