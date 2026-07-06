"""Tests for the negotiated path in the decision service."""

from datetime import datetime, timezone

import pytest

from network_b.contract.summary_schema import ENFORCEMENT_MAP, AccessRequest, Tier
from network_b.decision.decision_service import negotiate_decision, negotiation_enabled
from tests.test_decision_agent import RECOVERING, FakeClient


def access_request() -> AccessRequest:
    return AccessRequest(
        request_id="req-1",
        ue_pseudonym="UE_SIM_RECOVERING",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        timestamp=datetime.now(timezone.utc),
    )


def test_negotiation_flag_defaults_off(monkeypatch):
    monkeypatch.delenv("NEGOTIATION_ENABLED", raising=False)
    assert negotiation_enabled() is False


@pytest.mark.parametrize("value", ["1", "true", "True", "yes"])
def test_negotiation_flag_parses_truthy(monkeypatch, value):
    monkeypatch.setenv("NEGOTIATION_ENABLED", value)
    assert negotiation_enabled() is True


@pytest.mark.asyncio
async def test_negotiated_decision_carries_audit_fields():
    client = FakeClient(RECOVERING, answers={
        ("auth_stability", None): "medium",
        ("pdu_stability", None): "high",
        ("traffic_pattern", None): "volatile",
        ("trend", "traffic_spikes"): "decreasing",
        ("trend", "auth_failures"): "decreasing",
        ("anomaly_status", None): "resolved",
    })
    decision = await negotiate_decision(access_request(), client=client)

    assert decision is not None
    assert decision.final_tier == Tier.T2_MONITORED_ACCESS
    assert decision.policy_engine_metadata.negotiated is True
    assert decision.policy_engine_metadata.negotiation_transcript_hash == "f" * 64
    assert decision.policy_engine_metadata.negotiation_budget_spent == 90
    assert decision.simulated_enforcement == ENFORCEMENT_MAP[Tier.T2_MONITORED_ACCESS]
    # The negotiated path never receives a full six-field summary.
    assert decision.summary is None


@pytest.mark.asyncio
async def test_failed_negotiation_returns_none_for_fallback():
    client = FakeClient(RECOVERING, answers={}, fail_open=True)
    assert await negotiate_decision(access_request(), client=client) is None
