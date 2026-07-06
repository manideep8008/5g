"""Integration: the /v1/attestation/* endpoints enforce and emit signatures,
and a full negotiation works over the wire against seeded data."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from network_a import db
from network_a.api.app import app
from network_a.contract import request_signer as rs
from network_a.negotiation import boundary

SECRET = "integration-test-secret"

SESSION_PATH = "/v1/attestation/session"
QUERY_PATH = "/v1/attestation/query"
CLOSE_PATH = "/v1/attestation/close"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("HMAC_SECRET_KEY", SECRET)
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "true")

    # Force the in-memory store regardless of whether Postgres is reachable.
    async def _noop():
        return None

    monkeypatch.setattr(db, "init_pool", _noop)
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    boundary.reset_for_tests()
    yield
    db.reset_memory_store()
    boundary.reset_for_tests()


def signed_post(client: TestClient, path: str, payload: dict):
    body = rs.canonical_body(payload)
    headers = {**rs.sign("POST", path, body, key=SECRET), "content-type": "application/json"}
    return client.post(path, content=body, headers=headers)


def open_payload(pseudonym: str) -> dict:
    return {
        "request_id": "req-1",
        "ue_pseudonym": pseudonym,
        "requester_id": "network_b",
        "context": {
            "requested_slice": "eMBB",
            "requested_dnn": "internet",
            "requested_service": "standard_data",
        },
    }


@pytest.mark.integration
def test_unsigned_session_open_is_rejected_401():
    with TestClient(app) as client:
        resp = client.post(
            SESSION_PATH, content=rs.canonical_body(open_payload("UE_SIM_NORMAL"))
        )
    assert resp.status_code == 401


@pytest.mark.integration
def test_unknown_pseudonym_is_404():
    with TestClient(app) as client:
        resp = signed_post(client, SESSION_PATH, open_payload("UE_NEVER_SEEN"))
    assert resp.status_code == 404


@pytest.mark.integration
def test_full_negotiation_over_the_wire():
    with TestClient(app) as client:
        client.post("/v1/admin/seed-scenarios")

        opened = signed_post(client, SESSION_PATH, open_payload("UE_SIM_RECOVERING"))
        assert opened.status_code == 200
        rs.verify("POST", SESSION_PATH, opened.content, opened.headers, key=SECRET)
        session = opened.json()
        assert session["budget_remaining"] == 100
        assert session["minimal_attestation"]["behaviour_label"] == "anomalous"

        answered = signed_post(client, QUERY_PATH, {
            "session_id": session["session_id"],
            "predicate": "trend",
            "args": {"facet": "auth_failures"},
        })
        assert answered.status_code == 200
        rs.verify("POST", QUERY_PATH, answered.content, answered.headers, key=SECRET)
        query = answered.json()
        assert query["status"] == "answered"
        assert query["answer"] == "decreasing"
        assert query["budget_remaining"] == 90

        closed = signed_post(client, CLOSE_PATH, {
            "session_id": session["session_id"],
            "final_tier": "T2_MONITORED_ACCESS",
        })
        assert closed.status_code == 200
        rs.verify("POST", CLOSE_PATH, closed.content, closed.headers, key=SECRET)
        assert len(closed.json()["transcript_hash"]) == 64

        # The retired session id no longer resolves.
        gone = signed_post(client, QUERY_PATH, {
            "session_id": session["session_id"],
            "predicate": "anomaly_status",
            "args": {},
        })
        assert gone.status_code == 404
