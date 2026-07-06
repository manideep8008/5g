"""Tests for the decision agent's ask/decide loop.

The four scenario traces mirror Network A's seeded demo UEs: the answers
scripted here are exactly what A's grounding rules produce for those seeds
(see laptop_a tests/test_orchestrator.py). Tiers, question counts, and
budget spend are hand-computed from the belief model and pinned.
"""

import random

import pytest

from network_b.contract.negotiation_schemas import (
    CloseResponse,
    MinimalAttestation,
    NegotiationContext,
    QueryResponse,
    SessionOpenResponse,
)
from network_b.contract.summary_schema import TIER_ORDER, Tier
from network_b.negotiation.belief import tier_for
from network_b.negotiation.decision_agent import MAX_QUESTIONS, negotiate

CONTEXT = NegotiationContext(
    requested_slice="eMBB", requested_dnn="internet", requested_service="standard_data"
)

COSTS = {
    "auth_stability": 15,
    "pdu_stability": 15,
    "traffic_pattern": 15,
    "anomaly_status": 25,
    "trend": 10,
}


def attestation(label: str, anomaly: bool, rec: str, confidence: float) -> MinimalAttestation:
    return MinimalAttestation(
        behaviour_label=label, recent_anomaly=anomaly,
        recommendation=rec, confidence=confidence,
    )


NORMAL = attestation("normal", False, "T3_FULL_ACCESS", 1.0)
SUSPICIOUS = attestation("suspicious", True, "T2_MONITORED_ACCESS", 0.492)
RECOVERING = attestation("anomalous", True, "T1_RESTRICTED_ACCESS", 0.392)
ANOMALOUS = attestation("anomalous", True, "T1_RESTRICTED_ACCESS", 0.1017)


class FakeClient:
    """Scripted Network A: answers keyed by (predicate, facet arg)."""

    def __init__(
        self,
        attestation: MinimalAttestation,
        answers: dict[tuple[str, str | None], str],
        budget: int = 100,
        open_budget: int | None = None,
        grammar_version: int = 1,
        fail_open: bool = False,
        fail_query: bool = False,
    ):
        self.attestation = attestation
        self.answers = answers
        self.remaining = budget
        self.open_budget = open_budget if open_budget is not None else budget
        self.grammar_version = grammar_version
        self.fail_open = fail_open
        self.fail_query = fail_query
        self.asked: list[tuple[str, str | None]] = []
        self.closed_with: str | None = None

    async def open(self, req):
        if self.fail_open:
            return None
        return SessionOpenResponse(
            session_id="s-test",
            grammar_version=self.grammar_version,
            minimal_attestation=self.attestation,
            budget_total=100,
            budget_remaining=self.open_budget,
        )

    async def query(self, req):
        if self.fail_query:
            return None
        key = (req.predicate, req.args.get("facet"))
        self.asked.append(key)
        cost = COSTS[req.predicate]
        if cost > self.remaining:
            return QueryResponse(
                status="refused", reason="budget_exhausted",
                budget_remaining=self.remaining,
            )
        answer = self.answers.get(key)
        if answer is None:
            return QueryResponse(
                status="unavailable", reason="insufficient_data",
                budget_remaining=self.remaining,
            )
        self.remaining -= cost
        return QueryResponse(
            status="answered", answer=answer, cost=cost,
            budget_remaining=self.remaining, grounded=True,
        )

    async def close(self, req):
        self.closed_with = req.final_tier
        return CloseResponse(session_id=req.session_id, transcript_hash="f" * 64)


async def run(client: FakeClient):
    return await negotiate(client, "UE_TEST", CONTEXT, "req-1")


# ── the four demo scenarios ──────────────────────────────────────


@pytest.mark.asyncio
async def test_normal_ue_fast_path_zero_questions():
    client = FakeClient(NORMAL, answers={})
    outcome = await run(client)

    assert outcome.final_tier == Tier.T3_FULL_ACCESS
    assert outcome.stop_reason == "fast_path"
    assert outcome.questions_asked == 0
    assert outcome.budget_spent == 0
    assert client.closed_with == "T3_FULL_ACCESS"


@pytest.mark.asyncio
async def test_recovering_ue_negotiates_up_to_t2():
    """The thesis punchline: the fixed path pins this UE at T1; the
    negotiation establishes the trouble is historical and grants T2."""
    client = FakeClient(RECOVERING, answers={
        ("auth_stability", None): "medium",
        ("pdu_stability", None): "high",
        ("traffic_pattern", None): "volatile",
        ("trend", "traffic_spikes"): "decreasing",
        ("trend", "auth_failures"): "decreasing",
        ("anomaly_status", None): "resolved",
    })
    outcome = await run(client)

    assert outcome.final_tier == Tier.T2_MONITORED_ACCESS
    assert outcome.stop_reason == "tier_stable"
    assert outcome.questions_asked == 6
    assert outcome.budget_spent == 90
    assert outcome.floor_clipped is False
    assert outcome.facts["anomaly_status"] == "resolved"
    assert outcome.transcript_hash == "f" * 64


@pytest.mark.asyncio
async def test_suspicious_ue_stays_t1():
    """Same question order as recovering, opposite answers: ongoing trouble."""
    client = FakeClient(SUSPICIOUS, answers={
        ("auth_stability", None): "medium",
        ("pdu_stability", None): "high",
        ("traffic_pattern", None): "volatile",
        ("trend", "traffic_spikes"): "flat",
        ("trend", "auth_failures"): "flat",
        ("anomaly_status", None): "active",
    })
    outcome = await run(client)

    assert outcome.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert outcome.stop_reason == "tier_stable"
    assert outcome.budget_spent == 90
    assert outcome.risk_score == pytest.approx(0.60)


@pytest.mark.asyncio
async def test_anomalous_ue_confirmed_reject():
    client = FakeClient(ANOMALOUS, answers={
        ("auth_stability", None): "low",
        ("pdu_stability", None): "low",
        ("traffic_pattern", None): "volatile",
        ("trend", "auth_failures"): "flat",
        ("trend", "traffic_spikes"): "flat",
    })
    outcome = await run(client)

    assert outcome.final_tier == Tier.T0_REJECT
    assert outcome.stop_reason == "tier_stable"
    assert outcome.questions_asked == 5
    assert outcome.budget_spent == 65


# ── safety floor ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unresolved_anomaly_floor_caps_at_t2():
    """Clean facets but a flag whose status was never established: the
    interval stabilises at T3, and the floor clips to T2 — fail closed."""
    client = FakeClient(attestation("normal", True, "T3_FULL_ACCESS", 0.9), answers={
        ("auth_stability", None): "high",
        ("pdu_stability", None): "high",
        ("traffic_pattern", None): "stable",
    })
    outcome = await run(client)

    assert outcome.deterministic_max_tier == Tier.T3_FULL_ACCESS
    assert outcome.final_tier == Tier.T2_MONITORED_ACCESS
    assert outcome.floor_clipped is True
    assert ("anomaly_status", None) not in client.asked


# ── early stops ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unaffordable_questions_decide_conservatively():
    client = FakeClient(SUSPICIOUS, answers={("auth_stability", None): "medium"}, budget=20)
    outcome = await run(client)

    assert outcome.stop_reason == "budget_exhausted"
    assert outcome.questions_asked == 1
    assert outcome.budget_spent == 15
    # Conservative bound: unknowns held at worst case.
    assert outcome.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert outcome.final_tier == tier_for(outcome.risk_score)


@pytest.mark.asyncio
async def test_refused_query_decides_conservatively():
    """A drained shared window: A refuses the first paid question. The
    worst-case bound says T0, but nothing is established — uncertainty
    restricts (T1), it never rejects outright."""
    client = FakeClient(SUSPICIOUS, answers={}, budget=10, open_budget=100)
    outcome = await run(client)

    assert outcome.stop_reason == "budget_exhausted"
    assert outcome.budget_spent == 0
    assert tier_for(outcome.risk_score) == Tier.T0_REJECT
    assert outcome.final_tier == Tier.T1_RESTRICTED_ACCESS


@pytest.mark.asyncio
async def test_unavailable_facets_pin_worst_case():
    client = FakeClient(RECOVERING, answers={
        ("auth_stability", None): "medium",
        ("pdu_stability", None): "high",
        ("traffic_pattern", None): "volatile",
        # trends and anomaly_status missing → unavailable
    })
    outcome = await run(client)

    assert outcome.final_tier == Tier.T1_RESTRICTED_ACCESS
    assert outcome.stop_reason == "tier_stable"
    # Both trends pinned worst-case already stabilise the tier at T1, so the
    # agent never spends 25 points asking anomaly_status.
    assert outcome.questions_asked == 5
    assert ("anomaly_status", None) not in client.asked
    assert outcome.budget_spent == 45  # unavailable answers are never debited


# ── protocol failures fail closed ────────────────────────────────


@pytest.mark.asyncio
async def test_failed_open_returns_none():
    assert await run(FakeClient(NORMAL, answers={}, fail_open=True)) is None


@pytest.mark.asyncio
async def test_failed_query_returns_none():
    assert await run(FakeClient(SUSPICIOUS, answers={}, fail_query=True)) is None


@pytest.mark.asyncio
async def test_unsupported_grammar_version_returns_none():
    assert await run(FakeClient(NORMAL, answers={}, grammar_version=2)) is None


# ── the ceiling property ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_answer_sequence_exceeds_the_deterministic_ceiling():
    """Property: for any attestation and any in-domain answers, the granted
    tier never exceeds what the conservative risk bound allows."""
    domains = {
        "auth_stability": ["high", "medium", "low"],
        "pdu_stability": ["high", "medium", "low"],
        "traffic_pattern": ["stable", "moderate", "volatile"],
        "anomaly_status": ["none", "resolved", "active"],
        "trend": ["increasing", "flat", "decreasing"],
    }
    rng = random.Random(42)

    for _ in range(50):
        label = rng.choice(["normal", "suspicious", "anomalous"])
        att = attestation(
            label, rng.random() < 0.5,
            rng.choice(list(Tier)).value, round(rng.random(), 2),
        )

        class RandomClient(FakeClient):
            async def query(self, req):
                key = (req.predicate, req.args.get("facet"))
                if key not in self.answers and rng.random() >= 0.15:
                    self.answers[key] = rng.choice(domains[req.predicate])
                return await super().query(key and req)

        outcome = await run(RandomClient(att, answers={}))
        assert outcome is not None
        assert outcome.questions_asked <= MAX_QUESTIONS
        assert outcome.budget_spent <= 100
        # The floor can only lower the tier below the risk-derived ceiling,
        # with one deliberate exception: an early stop whose worst case says
        # T0 grants T1 instead when nothing established warrants rejection.
        ceiling = max(
            TIER_ORDER[tier_for(outcome.risk_score)],
            TIER_ORDER[Tier.T1_RESTRICTED_ACCESS],
        )
        assert TIER_ORDER[outcome.final_tier] <= ceiling
