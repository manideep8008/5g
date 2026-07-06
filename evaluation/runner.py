"""Replay the corpus through both paths and aggregate the results.

Disclosure accounting: the negotiated path reports actual budget points
spent. The fixed path always ships the same six-field summary; we price it
at what its facets would cost under the grammar — auth 15 + pdu 15 +
traffic 15 + slice inventory ≥ novelty 20 + anomaly ≥ status 25 = 90 points.
That is a *lower bound* (the raw slice list reveals more than a membership
answer), which biases the comparison against the negotiated path — the safe
direction for the thesis claim.
"""

from __future__ import annotations

import csv
import random
from dataclasses import asdict, dataclass
from pathlib import Path

from network_a import db
from network_a.negotiation import boundary
from network_a.negotiation.ledger import BudgetLedger
from network_a.summary.summary_generator import build_profile, generate_behavioural_summary
from network_b.contract.negotiation_schemas import NegotiationContext
from network_b.contract.summary_schema import TIER_ORDER, Tier
from network_b.contract.summary_schema import UeBehaviouralSummary as BSummary
from network_b.negotiation.decision_agent import negotiate
from network_b.policy.policy_engine import decide

from evaluation.local_client import LocalClient
from evaluation.scenarios import (
    ScenarioSpec,
    generate_scenarios,
    ground_truth,
    materialize,
    pseudonym_for,
)

FIXED_PATH_DISCLOSURE = 90
DEFAULT_BUDGETS = [10, 25, 50, 75, 100, 150, 200]

CONTEXT = NegotiationContext(
    requested_slice="eMBB", requested_dnn="internet", requested_service="standard_data"
)


@dataclass(frozen=True)
class Row:
    scenario_id: str
    archetype: str
    path: str                 # "fixed" | "negotiated"
    budget: int | None        # None for the fixed path
    truth_tier: str
    decided_tier: str
    exact: bool
    deviation: int            # TIER_ORDER[decided] − TIER_ORDER[truth]; >0 = over-grant
    disclosure: int
    questions: int
    stop_reason: str


def _row(spec, path, budget, truth, decided, disclosure, questions, stop) -> Row:
    return Row(
        scenario_id=spec.scenario_id,
        archetype=spec.archetype,
        path=path,
        budget=budget,
        truth_tier=truth.value,
        decided_tier=decided.value,
        exact=decided == truth,
        deviation=TIER_ORDER[decided] - TIER_ORDER[truth],
        disclosure=disclosure,
        questions=questions,
        stop_reason=stop,
    )


async def replay_fixed(spec: ScenarioSpec, truth: Tier) -> Row:
    """Today's path: the full six-field summary into the rules-only engine."""
    profile = await build_profile(pseudonym_for(spec))
    a_summary = generate_behavioural_summary(profile)
    b_summary = BSummary.model_validate(a_summary.model_dump(mode="json"))
    decision = decide(b_summary)
    return _row(
        spec, "fixed", None, truth, decision.tier,
        FIXED_PATH_DISCLOSURE, 0, "one_shot",
    )


async def replay_negotiated(spec: ScenarioSpec, truth: Tier, budget: int) -> Row:
    client = LocalClient(requester_id=f"eval-b{budget}")
    outcome = await negotiate(
        client, pseudonym_for(spec), CONTEXT, request_id=f"{spec.scenario_id}-b{budget}"
    )
    if outcome is None:  # protocol failure: the T1 fallback, zero disclosure
        return _row(
            spec, "negotiated", budget, truth,
            Tier.T1_RESTRICTED_ACCESS, 0, 0, "protocol_failure",
        )
    return _row(
        spec, "negotiated", budget, truth, outcome.final_tier,
        outcome.budget_spent, outcome.questions_asked, outcome.stop_reason,
    )


async def run_corpus(
    budgets: list[int] | None = None,
    seed: int = 7,
    counts: dict[str, int] | None = None,
) -> list[Row]:
    budgets = budgets or DEFAULT_BUDGETS

    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    boundary.reset_for_tests()

    rng = random.Random(seed)
    specs = generate_scenarios(rng, counts)
    truths: dict[str, Tier] = {}
    for spec in specs:
        await materialize(spec)
        truths[spec.scenario_id] = await ground_truth(spec)

    rows = [await replay_fixed(spec, truths[spec.scenario_id]) for spec in specs]

    grammar_window = boundary.load_grammar().budget_window_sec
    for budget in budgets:
        boundary.reset_for_tests()
        boundary._LEDGER = BudgetLedger(total=budget, window_sec=grammar_window)
        for spec in specs:
            rows.append(await replay_negotiated(spec, truths[spec.scenario_id], budget))

    boundary.reset_for_tests()
    return rows


@dataclass(frozen=True)
class Aggregate:
    path: str
    budget: int | None
    n: int
    accuracy: float
    overgrant_rate: float
    undergrant_rate: float
    mean_abs_deviation: float
    mean_disclosure: float
    mean_questions: float


def aggregate(rows: list[Row]) -> list[Aggregate]:
    groups: dict[tuple[str, int | None], list[Row]] = {}
    for row in rows:
        groups.setdefault((row.path, row.budget), []).append(row)

    out = []
    for (path, budget), group in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0)):
        n = len(group)
        out.append(Aggregate(
            path=path,
            budget=budget,
            n=n,
            accuracy=round(sum(r.exact for r in group) / n, 4),
            overgrant_rate=round(sum(r.deviation > 0 for r in group) / n, 4),
            undergrant_rate=round(sum(r.deviation < 0 for r in group) / n, 4),
            mean_abs_deviation=round(sum(abs(r.deviation) for r in group) / n, 4),
            mean_disclosure=round(sum(r.disclosure for r in group) / n, 2),
            mean_questions=round(sum(r.questions for r in group) / n, 2),
        ))
    return out


def write_csvs(rows: list[Row], aggregates: list[Aggregate], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, records in (("results.csv", rows), ("summary.csv", aggregates)):
        with open(out_dir / name, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(asdict(records[0]).keys()))
            writer.writeheader()
            writer.writerows(asdict(r) for r in records)


def print_summary(aggregates: list[Aggregate]) -> None:
    header = (
        f"{'path':<11} {'budget':>6} {'n':>4} {'accuracy':>9} "
        f"{'over':>6} {'under':>6} {'|dev|':>6} {'points':>7} {'quest.':>6}"
    )
    print(header)
    print("-" * len(header))
    for a in aggregates:
        budget = "-" if a.budget is None else str(a.budget)
        print(
            f"{a.path:<11} {budget:>6} {a.n:>4} {a.accuracy:>9.2%} "
            f"{a.overgrant_rate:>6.2%} {a.undergrant_rate:>6.2%} "
            f"{a.mean_abs_deviation:>6.2f} {a.mean_disclosure:>7.1f} {a.mean_questions:>6.2f}"
        )
