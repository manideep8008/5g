"""Figures for the evaluation chapter, generated from the result rows."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from evaluation.runner import Aggregate, Row

NEGOTIATED_COLOR = "#1D9E75"
FIXED_COLOR = "#D85A30"


def plot_frontier(aggregates: list[Aggregate], out_dir: Path) -> None:
    """The headline figure: tier accuracy vs mean disclosure per decision."""
    negotiated = [a for a in aggregates if a.path == "negotiated"]
    fixed = next(a for a in aggregates if a.path == "fixed")

    fig, ax = plt.subplots(figsize=(7, 4.5))
    xs = [a.mean_disclosure for a in negotiated]
    ys = [a.accuracy for a in negotiated]
    ax.plot(xs, ys, "o-", color=NEGOTIATED_COLOR, label="negotiated (budget sweep)")

    # Saturated budgets land on the same point; label each point once.
    points: dict[tuple[float, float], list[int]] = {}
    for a in negotiated:
        points.setdefault((a.mean_disclosure, a.accuracy), []).append(a.budget)
    for (x, y), budgets in points.items():
        label = f"b={budgets[0]}" if len(budgets) == 1 else f"b≥{min(budgets)}"
        ax.annotate(
            label, (x, y), textcoords="offset points", xytext=(6, -10), fontsize=8,
        )
    ax.plot(
        [fixed.mean_disclosure], [fixed.accuracy], "s",
        color=FIXED_COLOR, markersize=10, label="fixed six-field summary",
    )
    ax.set_xlabel("mean disclosure per decision (grammar points)")
    ax.set_ylabel("tier accuracy vs ground truth")
    ax.set_title("Privacy–utility frontier")
    ax.set_ylim(0, 1.05)
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "frontier.png", dpi=150)
    plt.close(fig)


def plot_archetype_accuracy(rows: list[Row], budget: int, out_dir: Path) -> None:
    """Where the negotiation wins: accuracy per archetype, both paths."""
    archetypes = sorted({r.archetype for r in rows})

    def accuracy(path: str, archetype: str) -> float:
        group = [
            r for r in rows
            if r.archetype == archetype and r.path == path
            and (r.budget == budget or r.budget is None)
        ]
        return sum(r.exact for r in group) / len(group)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    width = 0.38
    xs = range(len(archetypes))
    ax.bar(
        [x - width / 2 for x in xs],
        [accuracy("fixed", a) for a in archetypes],
        width, color=FIXED_COLOR, label="fixed",
    )
    ax.bar(
        [x + width / 2 for x in xs],
        [accuracy("negotiated", a) for a in archetypes],
        width, color=NEGOTIATED_COLOR, label=f"negotiated (budget {budget})",
    )
    ax.set_xticks(list(xs), archetypes)
    ax.set_ylabel("tier accuracy vs ground truth")
    ax.set_title("Accuracy by scenario archetype")
    ax.set_ylim(0, 1.05)
    ax.grid(axis="y", alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "archetype_accuracy.png", dpi=150)
    plt.close(fig)


def plot_disclosure(rows: list[Row], budget: int, out_dir: Path) -> None:
    """Disclosure spent per archetype: demand-driven vs always-everything."""
    archetypes = sorted({r.archetype for r in rows})
    fixed_cost = next(r.disclosure for r in rows if r.path == "fixed")

    means = []
    for archetype in archetypes:
        group = [
            r for r in rows
            if r.archetype == archetype and r.path == "negotiated" and r.budget == budget
        ]
        means.append(sum(r.disclosure for r in group) / len(group))

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(archetypes, means, color=NEGOTIATED_COLOR, label=f"negotiated (budget {budget})")
    ax.axhline(
        fixed_cost, color=FIXED_COLOR, linestyle="--",
        label=f"fixed summary ≈ {fixed_cost} points (lower bound)",
    )
    ax.set_ylabel("mean disclosure per decision (grammar points)")
    ax.set_title("Disclosure is demand-driven, not fixed")
    ax.grid(axis="y", alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "disclosure_by_archetype.png", dpi=150)
    plt.close(fig)


def render_all(
    rows: list[Row], aggregates: list[Aggregate], out_dir: Path, budget: int = 100
) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    plot_frontier(aggregates, out_dir)
    plot_archetype_accuracy(rows, budget, out_dir)
    plot_disclosure(rows, budget, out_dir)
    return ["frontier.png", "archetype_accuracy.png", "disclosure_by_archetype.png"]
