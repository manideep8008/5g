"""Tests for the signed session client: signatures both ways, fail closed."""

from __future__ import annotations

import httpx
import pytest

from network_b.contract import request_signer as rs
from network_b.contract.negotiation_schemas import (
    MinimalAttestation,
    NegotiationContext,
    SessionOpenRequest,
    SessionOpenResponse,
)
from network_b.negotiation.session_client import SESSION_PATH, SessionClient

SECRET = "client-test-secret"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("HMAC_SECRET_KEY", SECRET)
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "true")


def open_request() -> SessionOpenRequest:
    return SessionOpenRequest(
        request_id="req-1",
        ue_pseudonym="UE_HASH_ABC",
        context=NegotiationContext(
            requested_slice="eMBB", requested_dnn="internet",
            requested_service="standard_data",
        ),
    )


def open_response_body() -> bytes:
    payload = SessionOpenResponse(
        session_id="s-1",
        grammar_version=1,
        minimal_attestation=MinimalAttestation(
            behaviour_label="normal", recent_anomaly=False,
            recommendation="T3_FULL_ACCESS", confidence=1.0,
        ),
        budget_total=100,
        budget_remaining=100,
    ).model_dump(mode="json")
    return rs.canonical_body(payload)


def client_with(handler) -> SessionClient:
    transport = httpx.MockTransport(handler)
    return SessionClient(
        base_url="http://network-a", client=httpx.AsyncClient(transport=transport)
    )


@pytest.mark.asyncio
async def test_signed_roundtrip():
    def handler(request: httpx.Request) -> httpx.Response:
        # The client must have signed its request correctly.
        rs.verify("POST", SESSION_PATH, request.content, request.headers, key=SECRET)
        body = open_response_body()
        headers = {**rs.sign("POST", SESSION_PATH, body, key=SECRET),
                   "content-type": "application/json"}
        return httpx.Response(200, content=body, headers=headers)

    resp = await client_with(handler).open(open_request())

    assert resp is not None
    assert resp.session_id == "s-1"
    assert resp.budget_remaining == 100


@pytest.mark.asyncio
async def test_tampered_response_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        body = open_response_body()
        headers = {**rs.sign("POST", SESSION_PATH, body, key=SECRET),
                   "content-type": "application/json"}
        return httpx.Response(200, content=body + b" ", headers=headers)

    assert await client_with(handler).open(open_request()) is None


@pytest.mark.asyncio
async def test_unsigned_response_is_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=open_response_body(),
                              headers={"content-type": "application/json"})

    assert await client_with(handler).open(open_request()) is None


@pytest.mark.asyncio
async def test_http_error_status_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "no history"})

    assert await client_with(handler).open(open_request()) is None


@pytest.mark.asyncio
async def test_transport_error_fails_closed():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    assert await client_with(handler).open(open_request()) is None
