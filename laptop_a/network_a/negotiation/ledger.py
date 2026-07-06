"""Privacy budget ledger: bounds disclosure per (UE, requester, time window).

The ledger is the quantitative half of the privacy claim — the grammar bounds
what kinds of answers exist, the ledger bounds how many points' worth may be
spent. A debit is atomic with its answer: either the full cost is charged and
the answer ships, or nothing happens.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from network_a import db


class BudgetExhausted(Exception):
    """A debit would exceed the remaining budget; nothing was charged."""

    def __init__(self, requested: int, remaining: int):
        super().__init__(f"debit of {requested} exceeds remaining budget {remaining}")
        self.requested = requested
        self.remaining = remaining


@dataclass(frozen=True)
class BudgetStatus:
    total: int
    spent: int
    window_start: int

    @property
    def remaining(self) -> int:
        return self.total - self.spent


class BudgetLedger:
    """Windowed point budget over the shared storage backend."""

    def __init__(self, total: int, window_sec: int):
        if total <= 0 or window_sec <= 0:
            raise ValueError("total and window_sec must be positive")
        self.total = total
        self.window_sec = window_sec

    def _window_start(self, now: datetime | None) -> int:
        moment = now or datetime.now(timezone.utc)
        epoch = int(moment.timestamp())
        return epoch - (epoch % self.window_sec)

    async def status(
        self, pseudonym: str, requester_id: str, now: datetime | None = None
    ) -> BudgetStatus:
        window = self._window_start(now)
        spent = await db.get_budget_spent(pseudonym, requester_id, window)
        return BudgetStatus(total=self.total, spent=spent, window_start=window)

    async def debit(
        self, pseudonym: str, requester_id: str, cost: int, now: datetime | None = None
    ) -> BudgetStatus:
        """Atomically charge ``cost``; raise BudgetExhausted without charging
        if it would exceed the window total."""
        if cost <= 0:
            raise ValueError("cost must be positive")
        window = self._window_start(now)
        new_spent = await db.debit_budget(
            pseudonym, requester_id, window, cost, self.total
        )
        if new_spent is None:
            spent = await db.get_budget_spent(pseudonym, requester_id, window)
            raise BudgetExhausted(requested=cost, remaining=self.total - spent)
        return BudgetStatus(total=self.total, spent=new_spent, window_start=window)
