"""Tests for Network B attachment watcher."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from network_a.identity.ue_hasher import pseudonymise_imsi
from network_b.collector.attachment_watcher import trigger_access_decision


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
        self.calls.append((url, json))
        return self._response


@pytest.mark.unit
@pytest.mark.asyncio
async def test_trigger_uses_hmac_pseudonym() -> None:
    expected_pseudonym = pseudonymise_imsi("001010000000001")
    client = _FakeClient(
        _FakeResponse(
            status_code=200,
            payload={
                "final_tier": "T3_FULL_ACCESS",
                "risk_score": 0.1,
                "reason": "all stable",
            },
        )
    )

    decision = await trigger_access_decision(
        imsi="001010000000001",
        network_b_url="http://localhost:8002",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        client=client,  # type: ignore[arg-type]
    )

    assert decision is not None
    assert decision["final_tier"] == "T3_FULL_ACCESS"
    assert len(client.calls) == 1
    url, payload = client.calls[0]
    assert url == "http://localhost:8002/v1/access/request"
    assert payload["ue_pseudonym"] == expected_pseudonym
    assert payload["requested_slice"] == "eMBB"
    assert payload["requested_network"] == "Network_B"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_trigger_returns_none_on_non_200() -> None:
    client = _FakeClient(_FakeResponse(status_code=500, payload={"error": "boom"}))

    result = await trigger_access_decision(
        imsi="001010000000001",
        network_b_url="http://localhost:8002",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        client=client,  # type: ignore[arg-type]
    )

    assert result is None


@pytest.mark.unit
@pytest.mark.asyncio
async def test_trigger_returns_none_on_http_error() -> None:
    class _BrokenClient:
        async def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
            raise httpx.ConnectError("connection refused")

    result = await trigger_access_decision(
        imsi="001010000000001",
        network_b_url="http://localhost:8002",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        client=_BrokenClient(),  # type: ignore[arg-type]
    )

    assert result is None


@pytest.mark.unit
def test_pseudonym_matches_across_networks() -> None:
    """Both networks share the HMAC secret, so the same IMSI must
    produce the same pseudonym in both — that is the identity bridge."""
    network_a_view = pseudonymise_imsi("001010000000001")
    network_b_view = pseudonymise_imsi("001010000000001")
    assert network_a_view == network_b_view
