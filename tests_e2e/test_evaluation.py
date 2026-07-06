"""Smoke test for the evaluation harness: a miniature corpus through the
full pipeline, checking the invariants the thesis figures rest on."""

import pytest

from evaluation.runner import aggregate, run_corpus

TINY_COUNTS = {
    "clean": 2,
    "steady": 2,
    "recovering": 2,
    "degrading": 2,
    "hostile": 2,
    "sparse": 1,
}
N = sum(TINY_COUNTS.values())
BUDGETS = [25, 100]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_harness_invariants():
    rows = await run_corpus(budgets=BUDGETS, seed=11, counts=TINY_COUNTS)

    # One fixed row per scenario plus one negotiated row per budget.
    assert len(rows) == N * (1 + len(BUDGETS))
    assert all(r.stop_reason != "protocol_failure" for r in rows)

    aggregates = {(a.path, a.budget): a for a in aggregate(rows)}
    fixed = aggregates[("fixed", None)]
    negotiated_100 = aggregates[("negotiated", 100)]

    # Disclosure is demand-driven: the negotiated mean sits below the fixed
    # path's constant cost even at a full budget.
    assert negotiated_100.mean_disclosure < fixed.mean_disclosure

    # At full budget the agent has evidence for its rejections — no UE is
    # granted more than the full-information decision allows.
    assert negotiated_100.overgrant_rate == 0.0

    # Budgets are respected per decision.
    for row in rows:
        if row.path == "negotiated":
            assert row.disclosure <= row.budget


@pytest.mark.integration
@pytest.mark.asyncio
async def test_runs_are_reproducible():
    first = await run_corpus(budgets=[50], seed=11, counts=TINY_COUNTS)
    second = await run_corpus(budgets=[50], seed=11, counts=TINY_COUNTS)
    assert first == second
