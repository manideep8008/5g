"""End-to-end: Network B's real decision service negotiating with Network A's
real API — real HMAC signing, real grammar, real budget ledger, no mocks in
the decision path.

Network A's FastAPI app is mounted in-process via httpx.ASGITransport, which
is transport-for-transport what the two-laptop deployment does over the LAN.
The failure drills tamper with or sever that transport and assert the system
fails closed to T1 exactly like the protocol's failure table says.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

import network_a.db as adb
from network_a.api.app import app as network_a_app
from network_a.api.routes import seed_scenarios
from network_a.negotiation import boundary
from network_b.contract.summary_schema import AccessRequest, Tier
from network_b.decision import decision_service
from network_b.negotiation.session_client import SessionClient

SECRET = "e2e-shared-secret"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("HMAC_SECRET_KEY", SECRET)
    monkeypatch.setenv("REQUIRE_SIGNED_REQUESTS", "true")
    monkeypatch.setenv("NEGOTIATION_ENABLED", "true")

    adb._USE_MEMORY_FALLBACK = True
    adb.reset_memory_store()
    boundary.reset_for_tests()

    # Keep the audit log out of the filesystem during tests.
    monkeypatch.setattr(decision_service, "log_decision", lambda decision: None)
    # The one-shot fallback would otherwise dial a live Network A.
    monkeypatch.setattr(decision_service, "NETWORK_A_URL", "http://127.0.0.1:9")

    yield
    adb.reset_memory_store()
    boundary.reset_for_tests()


class TamperTransport(httpx.AsyncBaseTransport):
    """Passes ``clean`` responses through, then corrupts every later body —
    the wire-level equivalent of a man-in-the-middle."""

    def __init__(self, inner: httpx.AsyncBaseTransport, clean: int = 0):
        self._inner = inner
        self._clean = clean
        self._seen = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        self._seen += 1
        if self._seen <= self._clean:
            return response
        content = await response.aread()
        headers = {
            k: v for k, v in response.headers.items() if k.lower() != "content-length"
        }
        return httpx.Response(response.status_code, headers=headers, content=content + b" ")


def install_client(monkeypatch, transport: httpx.AsyncBaseTransport) -> None:
    """Make Network B's decision service negotiate over the given transport."""

    def factory() -> SessionClient:
        return SessionClient(
            base_url="http://network-a",
            client=httpx.AsyncClient(transport=transport),
        )

    monkeypatch.setattr(decision_service, "SessionClient", factory)


def live_network_a() -> httpx.AsyncBaseTransport:
    return httpx.ASGITransport(app=network_a_app)


def access_request(pseudonym: str, request_id: str = "req-e2e") -> AccessRequest:
    return AccessRequest(
        request_id=request_id,
        ue_pseudonym=pseudonym,
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        timestamp=datetime.now(timezone.utc),
    )


# ── the demo matrix, live over the wire ──────────────────────────

DEMO_MATRIX = [
    ("UE_SIM_NORMAL", Tier.T3_FULL_ACCESS, 0),
    ("UE_SIM_RECOVERING", Tier.T2_MONITORED_ACCESS, 90),
    ("UE_SIM_SUSPICIOUS", Tier.T1_RESTRICTED_ACCESS, 90),
    ("UE_SIM_ANOMALOUS", Tier.T0_REJECT, 65),
]


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.parametrize("pseudonym, expected_tier, expected_spent", DEMO_MATRIX)
async def test_demo_matrix_end_to_end(
    monkeypatch, pseudonym, expected_tier, expected_spent
):
    await seed_scenarios()
    install_client(monkeypatch, live_network_a())

    decision = await decision_service.handle_access_request(access_request(pseudonym))

    assert decision.final_tier == expected_tier
    meta = decision.policy_engine_metadata
    assert meta.negotiated is True
    assert meta.negotiation_budget_spent == expected_spent
    assert len(meta.negotiation_transcript_hash) == 64

    # Both sides' audit records reconcile: A's sealed transcript carries the
    # same hash and the same final tier B enforced.
    transcripts = adb._MEMORY_STORE["negotiation_transcript"]
    assert len(transcripts) == 1
    assert transcripts[0]["transcript_hash"] == meta.negotiation_transcript_hash
    assert transcripts[0]["final_tier"] == decision.final_tier.value
    assert transcripts[0]["pseudonym"] == pseudonym


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reattach_in_same_window_is_restricted_not_rejected(monkeypatch):
    """Second attach after the window budget is spent: the agent can afford
    nothing, and uncertainty restricts (T1) rather than rejects."""
    await seed_scenarios()
    install_client(monkeypatch, live_network_a())

    first = await decision_service.handle_access_request(
        access_request("UE_SIM_RECOVERING", "req-1")
    )
    assert first.final_tier == Tier.T2_MONITORED_ACCESS

    second = await decision_service.handle_access_request(
        access_request("UE_SIM_RECOVERING", "req-2")
    )
    assert second.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert second.policy_engine_metadata.negotiated is True
    assert second.policy_engine_metadata.negotiation_budget_spent == 0


# ── failure drills: every severed wire lands on T1 ───────────────


class DeadTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network A unreachable")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_dead_network_a_fails_closed_to_t1(monkeypatch):
    await seed_scenarios()
    install_client(monkeypatch, DeadTransport())

    decision = await decision_service.handle_access_request(
        access_request("UE_SIM_NORMAL")
    )

    # Even a clean UE gets restricted access when A cannot attest.
    assert decision.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert decision.policy_engine_metadata.negotiated is False
    assert "No summary available" in decision.reason


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tampered_channel_fails_closed_to_t1(monkeypatch):
    await seed_scenarios()
    install_client(monkeypatch, TamperTransport(live_network_a(), clean=0))

    decision = await decision_service.handle_access_request(
        access_request("UE_SIM_NORMAL")
    )

    assert decision.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert decision.policy_engine_metadata.negotiated is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mid_session_tamper_fails_closed_to_t1(monkeypatch):
    """Session opens fine, then the channel is compromised: the agent aborts
    the negotiation rather than trusting an unverifiable answer."""
    await seed_scenarios()
    install_client(monkeypatch, TamperTransport(live_network_a(), clean=1))

    decision = await decision_service.handle_access_request(
        access_request("UE_SIM_RECOVERING")
    )

    assert decision.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert decision.policy_engine_metadata.negotiated is False
