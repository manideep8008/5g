"""Tests for the privacy budget ledger (in-memory backend)."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from network_a import db
from network_a.negotiation.ledger import BudgetExhausted, BudgetLedger

UE = "UE_HASH_TEST"
REQUESTER = "network_b"
NOW = datetime(2026, 7, 6, 12, 30, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def reset_db():
    db._USE_MEMORY_FALLBACK = True
    db.reset_memory_store()
    yield
    db.reset_memory_store()


@pytest.fixture()
def ledger() -> BudgetLedger:
    return BudgetLedger(total=100, window_sec=3600)


@pytest.mark.asyncio
async def test_fresh_window_has_full_budget(ledger):
    status = await ledger.status(UE, REQUESTER, now=NOW)
    assert status.total == 100
    assert status.spent == 0
    assert status.remaining == 100


@pytest.mark.asyncio
async def test_debit_reduces_remaining(ledger):
    status = await ledger.debit(UE, REQUESTER, 25, now=NOW)
    assert status.spent == 25
    assert status.remaining == 75


@pytest.mark.asyncio
async def test_debit_to_exactly_zero_is_allowed(ledger):
    await ledger.debit(UE, REQUESTER, 60, now=NOW)
    status = await ledger.debit(UE, REQUESTER, 40, now=NOW)
    assert status.remaining == 0


@pytest.mark.asyncio
async def test_overdraft_raises_and_spends_nothing(ledger):
    await ledger.debit(UE, REQUESTER, 90, now=NOW)
    with pytest.raises(BudgetExhausted):
        await ledger.debit(UE, REQUESTER, 25, now=NOW)
    status = await ledger.status(UE, REQUESTER, now=NOW)
    assert status.spent == 90


@pytest.mark.asyncio
async def test_budgets_are_isolated_per_ue(ledger):
    await ledger.debit(UE, REQUESTER, 100, now=NOW)
    status = await ledger.status("UE_HASH_OTHER", REQUESTER, now=NOW)
    assert status.remaining == 100


@pytest.mark.asyncio
async def test_budgets_are_isolated_per_requester(ledger):
    await ledger.debit(UE, REQUESTER, 100, now=NOW)
    status = await ledger.status(UE, "network_c", now=NOW)
    assert status.remaining == 100


@pytest.mark.asyncio
async def test_window_rollover_refreshes_budget(ledger):
    await ledger.debit(UE, REQUESTER, 100, now=NOW)
    later = NOW + timedelta(seconds=3600)
    status = await ledger.status(UE, REQUESTER, now=later)
    assert status.remaining == 100


@pytest.mark.asyncio
async def test_same_window_accumulates_across_sessions(ledger):
    """Re-attaching within one window must not reset the budget."""
    await ledger.debit(UE, REQUESTER, 70, now=NOW)
    soon = NOW + timedelta(seconds=60)
    status = await ledger.status(UE, REQUESTER, now=soon)
    assert status.remaining == 30


@pytest.mark.asyncio
async def test_concurrent_debits_never_overspend(ledger):
    async def try_debit() -> bool:
        try:
            await ledger.debit(UE, REQUESTER, 10, now=NOW)
            return True
        except BudgetExhausted:
            return False

    results = await asyncio.gather(*(try_debit() for _ in range(25)))
    assert sum(results) == 10
    status = await ledger.status(UE, REQUESTER, now=NOW)
    assert status.spent == 100
