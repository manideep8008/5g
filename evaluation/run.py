"""Regenerate every evaluation artifact from scratch.

    python3 -m evaluation.run [--seed 7] [--budgets 10 25 50 75 100 150 200]
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from evaluation import runner
from evaluation.plots import render_all

DEFAULT_OUT = Path(__file__).resolve().parent / "results"


async def main(budgets: list[int], seed: int, out_dir: Path) -> None:
    rows = await runner.run_corpus(budgets=budgets, seed=seed)
    aggregates = runner.aggregate(rows)

    runner.write_csvs(rows, aggregates, out_dir)
    figures = render_all(rows, aggregates, out_dir, budget=max(b for b in budgets if b <= 100))

    runner.print_summary(aggregates)
    print(f"\n{len(rows)} rows → {out_dir}/results.csv, summary.csv")
    print(f"figures: {', '.join(figures)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Negotiated attestation evaluation")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--budgets", type=int, nargs="+", default=runner.DEFAULT_BUDGETS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    asyncio.run(main(args.budgets, args.seed, args.out))
