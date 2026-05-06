"""
Run all 3 experimental systems on the oracle dataset.

Systems:
1. full    — hybrid (LLM + safety floor) with summary from Network A
2. rule_without_summary — rules-only, no summary
3. single_llm — LLM-only, no safety floor

Each scenario is run with N seeds (default 3). For rules-based systems,
seeds don't affect output (deterministic), but we run them for consistency.

Output: data/results/experiment_results.json
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from network_a.summary.summary_schema import (
    AccessRequest,
    Tier,
    UeBehaviouralSummary,
)
from baselines.rule_without_summary import decide_without_summary
from baselines.single_llm_decision import decide_llm_only
from network_b.policy.llm_client import LlmConfig, load_llm_config
from network_b.policy.policy_engine import decide, decide_hybrid

ORACLE_PATH = Path(__file__).parent / "oracle_dataset.json"
RESULTS_PATH = Path(__file__).parents[1] / "data" / "results" / "experiment_results.json"


@dataclass
class RunResult:
    scenario_id: str
    system: str
    seed: int
    predicted_tier: str
    expected_tier: str
    correct: bool
    risk_score: float
    reason: str
    latency_ms: float
    llm_proposed_tier: str | None
    safety_floor_clipped: bool


def _make_access_request(scenario_id: str) -> AccessRequest:
    return AccessRequest(
        request_id=f"EXP-{scenario_id}",
        ue_pseudonym="UE_HASH_EVAL",
        requested_slice="eMBB",
        requested_dnn="internet",
        requested_service="standard_data",
        timestamp=datetime.now(timezone.utc),
    )


def _make_summary(summary_dict: dict) -> UeBehaviouralSummary:
    return UeBehaviouralSummary(**summary_dict)


async def run_full_system(
    summary: UeBehaviouralSummary,
    access_req: AccessRequest,
    llm_config: LlmConfig | None = None,
) -> tuple[str, float, str, str | None, bool]:
    start = time.perf_counter()
    result = await decide_hybrid(
        summary,
        llm_config=llm_config,
        requested_slice=access_req.requested_slice,
        requested_service=access_req.requested_service,
    )
    latency = (time.perf_counter() - start) * 1000

    return (
        result.tier.value,
        result.risk_score,
        result.reason,
        result.metadata.llm_proposed_tier,
        result.metadata.safety_floor_clipped,
        latency,
    )


def run_rule_without_summary(access_req: AccessRequest) -> tuple[str, float, str, float]:
    start = time.perf_counter()
    result = decide_without_summary(access_req)
    latency = (time.perf_counter() - start) * 1000
    return result.final_tier.value, result.risk_score, result.reason, latency


async def run_single_llm(
    summary: UeBehaviouralSummary,
    access_req: AccessRequest,
    llm_config: LlmConfig | None = None,
) -> tuple[str, float, str, str | None, float]:
    start = time.perf_counter()
    result = await decide_llm_only(summary, access_req, llm_config=llm_config)
    latency = (time.perf_counter() - start) * 1000
    return (
        result.final_tier.value,
        result.risk_score,
        result.reason,
        result.policy_engine_metadata.llm_proposed_tier,
        latency,
    )


async def run_all_experiments(
    oracle_path: Path | None = None,
    seeds: int = 3,
    llm_config: LlmConfig | None = None,
    use_llm: bool = True,
) -> list[dict]:
    path = oracle_path or ORACLE_PATH
    with open(path) as f:
        oracle = json.load(f)

    results: list[dict] = []
    total = len(oracle) * 3 * seeds
    completed = 0

    for scenario in oracle:
        summary = _make_summary(scenario["summary"])
        access_req = _make_access_request(scenario["scenario_id"])
        expected = scenario["expected_tier"]

        for seed in range(1, seeds + 1):
            # System 1: full (hybrid)
            if use_llm:
                tier, risk, reason, llm_proposed, clipped, latency = await run_full_system(
                    summary, access_req, llm_config
                )
            else:
                start = time.perf_counter()
                rule_result = decide(summary)
                latency = (time.perf_counter() - start) * 1000
                tier = rule_result.tier.value
                risk = rule_result.risk_score
                reason = rule_result.reason
                llm_proposed = None
                clipped = rule_result.metadata.safety_floor_clipped

            results.append({
                "scenario_id": scenario["scenario_id"],
                "category": scenario["category"],
                "system": "full",
                "seed": seed,
                "predicted_tier": tier,
                "expected_tier": expected,
                "correct": tier == expected,
                "risk_score": risk,
                "reason": reason,
                "latency_ms": round(latency, 2),
                "llm_proposed_tier": llm_proposed,
                "safety_floor_clipped": clipped,
            })

            # System 2: rule_without_summary
            start = time.perf_counter()
            rws_tier, rws_risk, rws_reason, rws_latency = run_rule_without_summary(access_req)
            results.append({
                "scenario_id": scenario["scenario_id"],
                "category": scenario["category"],
                "system": "rule_without_summary",
                "seed": seed,
                "predicted_tier": rws_tier,
                "expected_tier": expected,
                "correct": rws_tier == expected,
                "risk_score": rws_risk,
                "reason": rws_reason,
                "latency_ms": round(rws_latency, 2),
                "llm_proposed_tier": None,
                "safety_floor_clipped": False,
            })

            # System 3: single_llm
            if use_llm:
                slm_tier, slm_risk, slm_reason, slm_proposed, slm_latency = await run_single_llm(
                    summary, access_req, llm_config
                )
            else:
                start = time.perf_counter()
                rule_result = decide(summary)
                slm_latency = (time.perf_counter() - start) * 1000
                slm_tier = rule_result.tier.value
                slm_risk = rule_result.risk_score
                slm_reason = rule_result.reason + " (LLM unavailable fallback)"
                slm_proposed = None

            results.append({
                "scenario_id": scenario["scenario_id"],
                "category": scenario["category"],
                "system": "single_llm",
                "seed": seed,
                "predicted_tier": slm_tier,
                "expected_tier": expected,
                "correct": slm_tier == expected,
                "risk_score": slm_risk,
                "reason": slm_reason,
                "latency_ms": round(slm_latency, 2),
                "llm_proposed_tier": slm_proposed,
                "safety_floor_clipped": False,
            })

            completed += 3

    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Run evaluation experiments")
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--no-llm", action="store_true", help="Run without LLM (deterministic only)")
    parser.add_argument("--oracle", type=str, default=None)
    args = parser.parse_args()

    oracle_path = Path(args.oracle) if args.oracle else None
    use_llm = not args.no_llm

    print(f"Running experiments: seeds={args.seeds}, use_llm={use_llm}")

    results = asyncio.run(run_all_experiments(
        oracle_path=oracle_path,
        seeds=args.seeds,
        use_llm=use_llm,
    ))

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(results, indent=2))

    total = len(results)
    systems = {}
    for r in results:
        sys_name = r["system"]
        if sys_name not in systems:
            systems[sys_name] = {"correct": 0, "total": 0}
        systems[sys_name]["total"] += 1
        if r["correct"]:
            systems[sys_name]["correct"] += 1

    print(f"\nCompleted {total} runs across {len(results) // (args.seeds * 3)} scenarios")
    print(f"\nAccuracy by system:")
    for sys_name, counts in sorted(systems.items()):
        acc = counts["correct"] / counts["total"] * 100
        print(f"  {sys_name}: {counts['correct']}/{counts['total']} ({acc:.1f}%)")

    print(f"\nResults written to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
