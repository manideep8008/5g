"""Tests for the responder orchestrator: routing, verification, timeouts.

The end-to-end cases run every grammar predicate against the seeded demo UEs
— the offline version of what /v1/attestation/query will do in Phase 4.
"""

import asyncio

import pytest

from network_a import db
from network_a.api.routes import seed_scenarios
from network_a.negotiation.grammar import load_grammar
from network_a.summary.agents import orchestrator
from network_a.summary.agents.evidence import gather_evidence


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


def spec_for(predicate: str):
    return load_grammar().predicates[predicate]


def test_every_grammar_responder_is_registered():
    grammar = load_grammar()
    for spec in grammar.predicates.values():
        assert spec.responder in orchestrator.RESPONDERS, (
            f"grammar names responder '{spec.responder}' but no such responder exists"
        )


@pytest.mark.asyncio
async def test_unknown_ue_has_no_evidence():
    assert await gather_evidence("UE_NEVER_SEEN") is None


# ── demo-critical answers, per seeded scenario ───────────────────

RECOVERING_EXPECTED = {
    ("trend", ("facet", "auth_failures")): "decreasing",
    ("trend", ("facet", "traffic_spikes")): "decreasing",
    ("anomaly_status", None): "resolved",
    ("flag_age", None): "recent",
    ("auth_stability", None): "medium",
    ("pdu_stability", None): "high",
    ("traffic_pattern", None): "volatile",
    ("session_regularity", None): "regular",
}


@pytest.mark.asyncio
async def test_recovering_ue_full_predicate_sweep():
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_RECOVERING")

    for (predicate, arg), expected in RECOVERING_EXPECTED.items():
        args = {arg[0]: arg[1]} if arg else {}
        result = await orchestrator.answer_query(spec_for(predicate), args, evidence)
        assert result.status == "answered", f"{predicate}: {result.reason}"
        assert result.answer == expected, f"{predicate} answered {result.answer}"


@pytest.mark.asyncio
async def test_suspicious_ue_trouble_is_ongoing():
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_SUSPICIOUS")

    trend = await orchestrator.answer_query(
        spec_for("trend"), {"facet": "auth_failures"}, evidence
    )
    status = await orchestrator.answer_query(spec_for("anomaly_status"), {}, evidence)

    assert trend.answer == "flat"
    assert status.answer == "active"


@pytest.mark.asyncio
async def test_normal_ue_is_clean():
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_NORMAL")

    status = await orchestrator.answer_query(spec_for("anomaly_status"), {}, evidence)
    novelty = await orchestrator.answer_query(
        spec_for("resource_novelty"), {"kind": "slice", "value": "eMBB"}, evidence
    )

    assert status.answer == "none"
    assert novelty.answer == "known"


# ── failure behavior ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lying_responder_is_blocked_by_verifier(monkeypatch):
    """An answer the grounding rules do not entail must never leave."""
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_SUSPICIOUS")  # true trend: flat

    async def liar(predicate, args, ev):
        return "decreasing"

    monkeypatch.setitem(orchestrator.RESPONDERS, "trend", liar)
    result = await orchestrator.answer_query(
        spec_for("trend"), {"facet": "auth_failures"}, evidence
    )

    assert result.status == "unavailable"
    assert result.reason == "grounding_failed"
    assert result.answer is None


@pytest.mark.asyncio
async def test_slow_responder_times_out(monkeypatch):
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_NORMAL")

    async def sleepy(predicate, args, ev):
        await asyncio.sleep(1.0)

    monkeypatch.setitem(orchestrator.RESPONDERS, "anomaly", sleepy)
    result = await orchestrator.answer_query(
        spec_for("anomaly_status"), {}, evidence, timeout_sec=0.05
    )

    assert result.status == "unavailable"
    assert result.reason == "timeout"


@pytest.mark.asyncio
async def test_crashing_responder_fails_closed(monkeypatch):
    await seed_scenarios()
    evidence = await gather_evidence("UE_SIM_NORMAL")

    async def broken(predicate, args, ev):
        raise RuntimeError("boom")

    monkeypatch.setitem(orchestrator.RESPONDERS, "trend", broken)
    result = await orchestrator.answer_query(
        spec_for("trend"), {"facet": "auth_failures"}, evidence
    )

    assert result.status == "unavailable"
    assert result.reason == "responder_error"


@pytest.mark.asyncio
async def test_insufficient_data_is_unavailable():
    """A UE with one session has an empty older half — trend cannot ground."""
    from datetime import datetime, timezone

    await db.insert_identity("UE_SPARSE", "hmac_sparse", "Network_B")
    await db.insert_session(
        pseudonym="UE_SPARSE",
        started_at=datetime.now(timezone.utc),
        auth_attempts=5,
        auth_failures=0,
    )
    evidence = await gather_evidence("UE_SPARSE")

    result = await orchestrator.answer_query(
        spec_for("trend"), {"facet": "auth_failures"}, evidence
    )

    assert result.status == "unavailable"
    assert result.reason == "insufficient_data"
