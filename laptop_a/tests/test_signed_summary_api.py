"""Integration: the /v1/summary/request endpoint enforces and emits signatures."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from network_a.api.app import app
from network_a.contract import request_signer as rs
from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    SummaryResponse,
    TrafficPattern,
    UeBehaviouralSummary,
)

PATH = "/v1/summary/request"
SECRET = "integration-test-secret"


def _summary_request_body() -> bytes:
    return rs.canonical_body(
        {
            "request_id": "req-1",
            "ue_pseudonym": "UE_HASH_ABC",
            "requested_fields": ["behaviour_label"],
            "network_b_context": {
                "requested_slice": "eMBB",
                "requested_dnn": "internet",
                "requested_service": "standard_data",
            },
        }
    )


def _fake_summary() -> SummaryResponse:
    return SummaryResponse(
        request_id="req-1",
        ue_pseudonym="UE_HASH_ABC",
        summary=UeBehaviouralSummary(
            auth_stability=AuthStability.HIGH,
            pdu_session_stability=PduSessionStability.HIGH,
            traffic_pattern=TrafficPattern.STABLE,
            known_slice_usage=["eMBB"],
            recent_anomaly=False,
            behaviour_label=BehaviourLabel.NORMAL,
        ),
        network_a_recommendation="allow",
        confidence=0.9,
        issued_at=datetime(2026, 6, 29, tzinfo=timezone.utc),
    )


@pytest.fixture(autouse=True)
def _signing_env(monkeypatch):
    monkeypatch.setenv("HMAC_SECRET_KEY", SECRET)
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "true")
    # Keep the summary deterministic and DB-free; this suite is about signing.
    async def _stub(_req):
        return _fake_summary()

    monkeypatch.setattr("network_a.api.routes.generate_summary", _stub)


@pytest.mark.integration
def test_unsigned_request_is_rejected_401():
    with TestClient(app) as client:
        resp = client.post(PATH, content=_summary_request_body())
    assert resp.status_code == 401


@pytest.mark.integration
def test_tampered_signed_request_is_rejected_401():
    body = _summary_request_body()
    headers = rs.sign("POST", PATH, body, key=SECRET)
    with TestClient(app) as client:
        resp = client.post(PATH, content=body + b" ", headers=headers)
    assert resp.status_code == 401


@pytest.mark.integration
def test_signed_request_succeeds_and_response_is_signed():
    body = _summary_request_body()
    headers = {**rs.sign("POST", PATH, body, key=SECRET), "content-type": "application/json"}
    with TestClient(app) as client:
        resp = client.post(PATH, content=body, headers=headers)

    assert resp.status_code == 200
    # Network A's response carries its own provenance signature, and it verifies.
    rs.verify("POST", PATH, resp.content, resp.headers, key=SECRET)
    assert resp.json()["ue_pseudonym"] == "UE_HASH_ABC"
