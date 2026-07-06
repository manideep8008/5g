from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from network_a import db
from network_a.api.signing import require_signed_request, signed_json_response
from network_a.summary.summary_generator import generate_summary
from network_a.summary.summary_schema import SummaryRequest

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok", "service": "network_a", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.post("/summary/request", dependencies=[Depends(require_signed_request)])
async def request_summary(req: SummaryRequest, request: Request):
    try:
        response = await generate_summary(req)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if response is None:
        raise HTTPException(status_code=404, detail=f"No summary available for {req.ue_pseudonym}")

    # Sign the response body so Network B can verify it really came from us.
    return signed_json_response("POST", request.url.path, response.model_dump(mode="json"))


# ── Admin / demo endpoints ───────────────────────────────────────

_SCENARIOS = {
    "normal": {
        "pseudonym": "UE_SIM_NORMAL",
        "sessions": 10,
        "auth_attempts": 5,
        "auth_failures": 0,
        "pdu_attempts": 3,
        "pdu_failures": 0,
        "spike_count": 0,
        "risk_flags": [],
        "description": "Clean UE — zero failures, stable traffic",
    },
    "suspicious": {
        "pseudonym": "UE_SIM_SUSPICIOUS",
        "sessions": 8,
        "auth_attempts": 5,
        "auth_failures": 1,       # 20% failure rate, steady over the window
        "pdu_attempts": 3,
        "pdu_failures": 0,
        "spike_count": [1, 0, 1, 0, 1, 0, 1, 0],   # spikes in half the sessions
        "risk_flags": [{"flag_type": "auth_burst", "severity": "medium"}],
        "description": "Moderate auth failures + traffic spikes, ongoing",
    },
    "recovering": {
        "pseudonym": "UE_SIM_RECOVERING",
        "sessions": 8,
        "auth_attempts": 5,
        "auth_failures": [2, 2, 2, 2, 0, 0, 0, 0],  # trouble in the older half only
        "pdu_attempts": 3,
        "pdu_failures": 0,
        "spike_count": [2, 2, 2, 2, 0, 0, 0, 0],
        "risk_flags": [{"flag_type": "auth_burst", "severity": "medium"}],
        "description": "Recovered UE — window totals match a troubled UE but all "
                       "failures/spikes are in the older half; flag never cleared. "
                       "Only trend/anomaly_status queries can tell it apart.",
    },
    "anomalous": {
        "pseudonym": "UE_SIM_ANOMALOUS",
        "sessions": 5,
        "auth_attempts": 5,
        "auth_failures": 3,       # 60% failure rate
        "pdu_attempts": 3,
        "pdu_failures": 2,        # 67% PDU failure rate
        "spike_count": 1,         # spikes in every session
        "risk_flags": [
            {"flag_type": "auth_anomaly", "severity": "high"},
            {"flag_type": "traffic_flood", "severity": "critical"},
        ],
        "description": "High failure rates + active risk flags → REJECT",
    },
}


def _per_session(value: int | list[int], i: int) -> int:
    """Scenario fields may be a single value or a per-session series
    (index 0 = oldest session), so seeds can have temporal shape."""
    return value[i] if isinstance(value, list) else value


@router.post("/admin/seed-scenarios")
async def seed_scenarios():
    """Inject 4 simulated UEs (normal / suspicious / recovering / anomalous)
    into the live store so the summary and access-decision APIs return
    different classifications.  Safe to call multiple times — identities are
    deduplicated."""
    results = []
    now = datetime.now(timezone.utc)

    for label, sc in _SCENARIOS.items():
        pseudonym = sc["pseudonym"]
        await db.insert_identity(pseudonym, f"hmac_simulated_{label}", "Network_B")

        for i in range(sc["sessions"]):
            await db.insert_session(
                pseudonym=pseudonym,
                started_at=now - timedelta(hours=sc["sessions"] - i),
                ended_at=now - timedelta(hours=sc["sessions"] - i - 1),
                duration_sec=3600,
                registration_success=True,
                auth_attempts=_per_session(sc["auth_attempts"], i),
                auth_failures=_per_session(sc["auth_failures"], i),
                pdu_attempts=_per_session(sc["pdu_attempts"], i),
                pdu_failures=_per_session(sc["pdu_failures"], i),
                spike_count=_per_session(sc["spike_count"], i),
                requested_slice="eMBB",
                requested_dnn="oai",
                bytes_uplink=5000 + i * 1000,
                bytes_downlink=20000 + i * 3000,
                peak_throughput_kbps=100 + i * 50,
            )

        for flag in sc["risk_flags"]:
            await db.insert_risk_flag(
                pseudonym, flag["flag_type"], flag["severity"],
                {"source": "scenario_seed"},
            )

        results.append({
            "pseudonym": pseudonym,
            "profile": label,
            "sessions_created": sc["sessions"],
            "description": sc["description"],
        })

    return {"seeded": results}
