"""Network B signs its summary requests and verifies Network A's response.

A bad/missing response signature must fail closed: ``fetch_summary`` returns
None, and ``handle_access_request`` then drops the UE to T1 (restricted).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from network_b.contract import request_signer as rs
from network_b.contract.summary_schema import AccessRequest, Tier
from network_b.decision import decision_service as svc

PATH = "/v1/summary/request"
SECRET = "fetch-test-secret"


def _summary_payload() -> dict[str, Any]:
    return {
        "request_id": "req-1",
        "ue_pseudonym": "UE_HASH_ABC",
        "summary": {
            "auth_stability": "high",
            "pdu_session_stability": "high",
            "traffic_pattern": "stable",
            "known_slice_usage": ["eMBB"],
            "recent_anomaly": False,
            "behaviour_label": "normal",
        },
        "network_a_recommendation": "allow",
        "confidence": 0.9,
        "privacy_level": "summary_only",
        "issued_at": datetime(2026, 6, 29, tzinfo=timezone.utc).isoformat(),
        "summary_window_sec": 86400,
    }


class _FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
        self.status_code = status_code
        self.content = content
        self.headers = headers

    def json(self) -> Any:
        import json

        return json.loads(self.content)


class _FakeClient:
    """Echoes a canned response and records the outbound request for assertions."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    async def post(self, url: str, *, content: bytes, headers: dict[str, str]) -> _FakeResponse:
        self.calls.append({"url": url, "content": content, "headers": headers})
        return self._response


def _signed_response(*, key: str = SECRET, status: int = 200) -> _FakeResponse:
    body = rs.canonical_body(_summary_payload())
    headers = rs.sign("POST", PATH, body, key=key)
    return _FakeResponse(status, body, headers)


def _access_req() -> AccessRequest:
    return AccessRequest(
        request_id="req-1",
        ue_pseudonym="UE_HASH_ABC",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        timestamp=datetime(2026, 6, 29, tzinfo=timezone.utc),
    )


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("HMAC_SECRET_KEY", SECRET)
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "true")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_summary_signs_outbound_and_accepts_valid_response():
    client = _FakeClient(_signed_response())
    result = await svc.fetch_summary("UE_HASH_ABC", "req-1", _access_req(), client=client)

    assert result is not None
    assert result.ue_pseudonym == "UE_HASH_ABC"
    # The outbound request was itself signed and verifies against the shared key.
    call = client.calls[0]
    assert call["url"].endswith(PATH)
    rs.verify("POST", PATH, call["content"], call["headers"], key=SECRET)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_summary_rejects_bad_response_signature():
    client = _FakeClient(_signed_response(key="attacker-key"))
    result = await svc.fetch_summary("UE_HASH_ABC", "req-1", _access_req(), client=client)
    assert result is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_summary_rejects_unsigned_response():
    body = rs.canonical_body(_summary_payload())
    client = _FakeClient(_FakeResponse(200, body, headers={}))
    result = await svc.fetch_summary("UE_HASH_ABC", "req-1", _access_req(), client=client)
    assert result is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_fetch_summary_allows_unsigned_when_disabled(monkeypatch):
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "false")
    body = rs.canonical_body(_summary_payload())
    client = _FakeClient(_FakeResponse(200, body, headers={}))
    result = await svc.fetch_summary("UE_HASH_ABC", "req-1", _access_req(), client=client)
    assert result is not None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_handle_access_request_fails_closed_to_t1_on_bad_signature(monkeypatch):
    async def _bad(*_args, **_kwargs):
        return None

    monkeypatch.setattr(svc, "fetch_summary", _bad)
    decision = await svc.handle_access_request(_access_req())
    assert decision.final_tier == Tier.T1_RESTRICTED_ACCESS
