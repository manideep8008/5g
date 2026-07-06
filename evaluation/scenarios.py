"""Synthetic UE corpus with ground truth by construction.

Each archetype is a generative recipe for session histories with a known
temporal shape (steady, front-loaded, back-loaded, ...). Ground truth for a
scenario is the *full-information decision*: the belief-model risk computed
with every facet, trend, and anomaly status filled in from Network A's own
grounding rules over the materialized data — i.e. what an oracle Network B
with unlimited budget would decide. The evaluation then measures how close
each path gets under partial information, and at what disclosure cost.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from network_a import db
from network_a.summary.agents import grounding
from network_a.summary.agents.evidence import gather_evidence
from network_a.summary.summary_generator import generate_behavioural_summary
from network_b.contract.summary_schema import Tier
from network_b.negotiation import belief
from network_b.negotiation.belief import (
    Beliefs,
    apply_negotiated_floor,
    risk_bounds,
    tier_for,
)

NOW = datetime(2026, 7, 6, 12, 0, tzinfo=timezone.utc)

# How many instances of each archetype (jittered individually by the rng).
DEFAULT_COUNTS = {
    "clean": 10,
    "steady": 8,
    "recovering": 8,
    "degrading": 8,
    "hostile": 8,
    "sparse": 4,
}


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    archetype: str
    auth_failures: list[int]      # per session, index 0 = oldest
    pdu_failures: list[int]
    spike_count: list[int]
    auth_attempts: int = 5
    pdu_attempts: int = 3
    flags: int = 0

    @property
    def sessions(self) -> int:
        return len(self.auth_failures)


def _make(archetype: str, i: int, rng: random.Random) -> ScenarioSpec:
    def series(n: int, first_half: int, second_half: int) -> list[int]:
        return [first_half] * (n // 2) + [second_half] * (n - n // 2)

    if archetype == "clean":
        n = rng.randint(8, 12)
        return ScenarioSpec(f"clean-{i}", archetype, [0] * n, [0] * n, [0] * n)

    if archetype == "steady":
        n = rng.randint(8, 10)
        fail = rng.randint(1, 2)
        spikes = [rng.randint(0, 1) for _ in range(n)]
        return ScenarioSpec(
            f"steady-{i}", archetype, [fail] * n, [0] * n, spikes, flags=1
        )

    if archetype == "recovering":
        n = rng.choice([8, 10])
        fail = rng.randint(2, 3)
        return ScenarioSpec(
            f"recovering-{i}", archetype,
            series(n, fail, 0), [0] * n, series(n, 2, 0), flags=1,
        )

    if archetype == "degrading":
        n = rng.choice([8, 10])
        fail = rng.randint(2, 3)
        return ScenarioSpec(
            f"degrading-{i}", archetype,
            series(n, 0, fail), [0] * n, series(n, 0, 2), flags=1,
        )

    if archetype == "hostile":
        n = rng.randint(5, 8)
        return ScenarioSpec(
            f"hostile-{i}", archetype,
            [rng.randint(3, 4)] * n,
            [rng.randint(1, 2)] * n,
            [rng.randint(1, 2)] * n,
            flags=2,
        )

    if archetype == "sparse":
        n = rng.randint(1, 2)
        return ScenarioSpec(
            f"sparse-{i}", archetype,
            [rng.randint(0, 1)] * n, [0] * n, [0] * n,
            flags=rng.randint(0, 1),
        )

    raise ValueError(f"unknown archetype {archetype}")


def generate_scenarios(
    rng: random.Random, counts: dict[str, int] | None = None
) -> list[ScenarioSpec]:
    counts = counts or DEFAULT_COUNTS
    return [
        _make(archetype, i, rng)
        for archetype, n in counts.items()
        for i in range(n)
    ]


def pseudonym_for(spec: ScenarioSpec) -> str:
    return f"UE_EVAL_{spec.scenario_id.upper().replace('-', '_')}"


async def materialize(spec: ScenarioSpec) -> str:
    """Insert the scenario's sessions and flags into Network A's store."""
    pseudonym = pseudonym_for(spec)
    await db.insert_identity(pseudonym, f"hmac_{spec.scenario_id}", "Network_B")

    for i in range(spec.sessions):
        await db.insert_session(
            pseudonym=pseudonym,
            started_at=NOW - timedelta(hours=spec.sessions - i),
            ended_at=NOW - timedelta(hours=spec.sessions - i - 1),
            duration_sec=3600,
            registration_success=True,
            auth_attempts=spec.auth_attempts,
            auth_failures=spec.auth_failures[i],
            pdu_attempts=spec.pdu_attempts,
            pdu_failures=spec.pdu_failures[i],
            spike_count=spec.spike_count[i],
            requested_slice="eMBB",
            requested_dnn="internet",
            bytes_uplink=5000 + i * 1000,
            bytes_downlink=20000 + i * 3000,
            peak_throughput_kbps=100 + i * 50,
        )

    for f in range(spec.flags):
        await db.insert_risk_flag(
            pseudonym, "auth_burst", "medium", {"source": f"eval_seed_{f}"}
        )
    return pseudonym


# Facet key ↔ (predicate, args) pairs an oracle would know.
_ORACLE_QUERIES = [
    (belief.AUTH, "auth_stability", {}),
    (belief.PDU, "pdu_stability", {}),
    (belief.TRAFFIC, "traffic_pattern", {}),
    (belief.ANOMALY, "anomaly_status", {}),
    (belief.TREND_AUTH, "trend", {"facet": "auth_failures"}),
    (belief.TREND_TRAFFIC, "trend", {"facet": "traffic_spikes"}),
]


async def ground_truth(spec: ScenarioSpec) -> Tier:
    """The full-information decision: every groundable fact known, the same
    risk semantics and floor both paths use. Facets even an oracle cannot
    ground (sparse histories) stay pinned at worst case."""
    pseudonym = pseudonym_for(spec)
    evidence = await gather_evidence(pseudonym, now=NOW)
    summary = generate_behavioural_summary(evidence.profile)

    beliefs = Beliefs(
        behaviour_label=summary.behaviour_label.value,
        recent_anomaly=summary.recent_anomaly,
    )
    for facet_key, predicate, args in _ORACLE_QUERIES:
        answer = grounding.ground(predicate, args, evidence)
        if answer is None:
            beliefs.unresolvable.add(facet_key)
        else:
            beliefs.facts[facet_key] = answer

    risk_min, risk_max = risk_bounds(beliefs)
    tier = tier_for(risk_max)
    if tier == Tier.T0_REJECT and tier_for(risk_min) != Tier.T0_REJECT:
        tier = Tier.T1_RESTRICTED_ACCESS  # same uncertainty rule as the agent
    tier, _, _ = apply_negotiated_floor(tier, beliefs)
    return tier
