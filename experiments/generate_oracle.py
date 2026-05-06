"""
Generate oracle dataset for evaluation.

Produces ~75 scenarios:
- ~55 unambiguous (auto-generated from bucket space where all fields agree)
- ~15 conflicting-signal (hand-labeled, requires LLM reasoning)
- 5 adversarial (prompt-injection attempts)

Output: experiments/oracle_dataset.json
"""
from __future__ import annotations

import json
import itertools
from dataclasses import asdict, dataclass
from pathlib import Path

from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    Tier,
    TrafficPattern,
)
from network_b.policy.risk_score import compute_risk_score
from network_b.policy.tier_mapper import risk_to_max_tier

OUTPUT_PATH = Path(__file__).parent / "oracle_dataset.json"


@dataclass
class OracleScenario:
    scenario_id: str
    category: str  # "unambiguous" | "conflicting" | "adversarial"
    summary: dict
    expected_tier: str
    reasoning: str
    difficulty: str  # "easy" | "medium" | "hard"


def _summary_dict(
    auth: AuthStability,
    pdu: PduSessionStability,
    traffic: TrafficPattern,
    anomaly: bool,
    behaviour: BehaviourLabel,
    slices: list[str] | None = None,
) -> dict:
    return {
        "auth_stability": auth.value,
        "pdu_session_stability": pdu.value,
        "traffic_pattern": traffic.value,
        "known_slice_usage": slices or ["eMBB"],
        "recent_anomaly": anomaly,
        "behaviour_label": behaviour.value,
    }


def _to_pydantic(d: dict):
    from network_a.summary.summary_schema import UeBehaviouralSummary
    return UeBehaviouralSummary(**d)


def generate_unambiguous_scenarios() -> list[OracleScenario]:
    candidates: dict[str, list] = {
        Tier.T3_FULL_ACCESS.value: [],
        Tier.T2_MONITORED_ACCESS.value: [],
        Tier.T1_RESTRICTED_ACCESS.value: [],
        Tier.T0_REJECT.value: [],
    }
    seen_summaries: set[str] = set()

    TIER_MARGINS = {
        Tier.T3_FULL_ACCESS: (0.0, 0.20),
        Tier.T2_MONITORED_ACCESS: (0.22, 0.48),
        Tier.T1_RESTRICTED_ACCESS: (0.52, 0.78),
        Tier.T0_REJECT: (0.82, 1.0),
    }

    for auth in AuthStability:
        for pdu in PduSessionStability:
            for traffic in TrafficPattern:
                for anomaly in [False, True]:
                    for behaviour in BehaviourLabel:
                        summary = _summary_dict(auth, pdu, traffic, anomaly, behaviour)
                        key = json.dumps(summary, sort_keys=True)
                        if key in seen_summaries:
                            continue

                        pydantic_summary = _to_pydantic(summary)
                        risk = compute_risk_score(pydantic_summary)
                        tier = risk_to_max_tier(risk)

                        if anomaly and tier == Tier.T3_FULL_ACCESS:
                            continue

                        margin_lo, margin_hi = TIER_MARGINS[tier]
                        if margin_lo <= risk <= margin_hi:
                            seen_summaries.add(key)
                            candidates[tier.value].append((summary, risk, auth, pdu, traffic, anomaly, behaviour))
                        elif _fields_agree(auth, pdu, traffic, anomaly, behaviour):
                            seen_summaries.add(key)
                            candidates[tier.value].append((summary, risk, auth, pdu, traffic, anomaly, behaviour))

    TARGET_PER_TIER = {
        Tier.T3_FULL_ACCESS.value: 15,
        Tier.T2_MONITORED_ACCESS.value: 16,
        Tier.T1_RESTRICTED_ACCESS.value: 14,
        Tier.T0_REJECT.value: 10,
    }

    scenarios = []
    scenario_num = 1

    for tier_val, target in TARGET_PER_TIER.items():
        pool = candidates[tier_val]
        pool.sort(key=lambda x: x[1])
        selected = pool[:target]

        for summary, risk, auth, pdu, traffic, anomaly, behaviour in selected:
            tier = Tier(tier_val)
            scenarios.append(OracleScenario(
                scenario_id=f"UNAMB-{scenario_num:03d}",
                category="unambiguous",
                summary=summary,
                expected_tier=tier_val,
                reasoning=_generate_unambiguous_reasoning(auth, pdu, traffic, anomaly, behaviour, tier),
                difficulty="easy",
            ))
            scenario_num += 1

    return scenarios


def _fields_agree(
    auth: AuthStability,
    pdu: PduSessionStability,
    traffic: TrafficPattern,
    anomaly: bool,
    behaviour: BehaviourLabel,
) -> bool:
    level_map = {
        AuthStability.HIGH: 0, AuthStability.MEDIUM: 1, AuthStability.LOW: 2,
        PduSessionStability.HIGH: 0, PduSessionStability.MEDIUM: 1, PduSessionStability.LOW: 2,
        TrafficPattern.STABLE: 0, TrafficPattern.MODERATE: 1, TrafficPattern.VOLATILE: 2,
        BehaviourLabel.NORMAL: 0, BehaviourLabel.SUSPICIOUS: 1, BehaviourLabel.ANOMALOUS: 2,
    }

    levels = [level_map[auth], level_map[pdu], level_map[traffic], level_map[behaviour]]
    anomaly_level = 2 if anomaly else 0

    all_vals = levels + [anomaly_level]
    return max(all_vals) - min(all_vals) <= 1


def _generate_unambiguous_reasoning(auth, pdu, traffic, anomaly, behaviour, tier) -> str:
    if tier == Tier.T3_FULL_ACCESS:
        return "All indicators stable and trustworthy — full access appropriate."
    elif tier == Tier.T2_MONITORED_ACCESS:
        return "Moderate risk indicators present — monitoring warranted."
    elif tier == Tier.T1_RESTRICTED_ACCESS:
        return "Multiple elevated risk indicators — restrict access."
    else:
        return "Severe risk across all indicators — reject access."


def generate_conflicting_scenarios() -> list[OracleScenario]:
    scenarios = []

    conflicting_cases = [
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.STABLE, True, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Despite stable history, recent anomaly flag requires monitoring. Safety floor enforces T2 max.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.HIGH, TrafficPattern.STABLE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Low auth stability is a strong negative signal despite other good indicators. Safety floor enforces T1.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.LOW, TrafficPattern.STABLE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "PDU instability with otherwise good profile warrants monitoring but not restriction.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.VOLATILE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Volatile traffic with stable auth suggests bursty usage, not malice. Monitor.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.MEDIUM, PduSessionStability.HIGH, TrafficPattern.STABLE, True, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Mixed signals: recent anomaly + suspicious label, but auth is only medium. Monitor closely.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.MEDIUM, TrafficPattern.MODERATE, False, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Suspicious label with moderate indicators — could be legitimate heavy use. Monitor.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.MEDIUM, PduSessionStability.MEDIUM, TrafficPattern.STABLE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Auth and PDU both medium — borderline case. Conservative monitoring appropriate.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.STABLE, False, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Suspicious behaviour label despite stable metrics — label may lag. Monitor.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.MEDIUM, TrafficPattern.STABLE, False, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Low auth stability + suspicious label — restrict despite stable traffic.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.MEDIUM, PduSessionStability.LOW, TrafficPattern.MODERATE, True, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Recent anomaly flag caps at T2. PDU low is concerning but behaviour label is normal.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.VOLATILE, True, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Anomaly flag caps at T2. Good auth/PDU but volatile traffic + suspicious — monitor.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.MEDIUM, PduSessionStability.HIGH, TrafficPattern.VOLATILE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Volatile traffic + medium auth creates enough concern for monitoring.",
            "difficulty": "medium",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.HIGH, TrafficPattern.STABLE, True, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Low auth + anomaly + suspicious — multiple red flags override good PDU/traffic.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.LOW, TrafficPattern.VOLATILE, False, BehaviourLabel.SUSPICIOUS),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "PDU instability + volatile traffic is concerning, but auth is solid. Monitor.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.MEDIUM, PduSessionStability.MEDIUM, TrafficPattern.MODERATE, True, BehaviourLabel.SUSPICIOUS, ["URLLC"]),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "All medium + anomaly flag + URLLC slice request. Anomaly caps at T2.",
            "difficulty": "hard",
        },
    ]

    for i, case in enumerate(conflicting_cases, 1):
        scenarios.append(OracleScenario(
            scenario_id=f"CONFL-{i:03d}",
            category="conflicting",
            summary=case["summary"],
            expected_tier=case["expected_tier"],
            reasoning=case["reasoning"],
            difficulty=case["difficulty"],
        ))

    return scenarios


def generate_adversarial_scenarios() -> list[OracleScenario]:
    scenarios = []

    adversarial_cases = [
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.STABLE, True, BehaviourLabel.NORMAL),
            "expected_tier": "T2_MONITORED_ACCESS",
            "reasoning": "Anomaly flag present despite 'perfect' other fields — classic injection pattern. Safety floor clips to T2.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.HIGH, TrafficPattern.STABLE, False, BehaviourLabel.NORMAL),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Low auth masked by good other fields — injection might convince LLM to ignore. Safety floor clips to T1.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.HIGH, PduSessionStability.HIGH, TrafficPattern.STABLE, False, BehaviourLabel.ANOMALOUS),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Anomalous behaviour label contradicts stable metrics — manipulation attempt. Safety floor clips to T1.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.HIGH, TrafficPattern.STABLE, True, BehaviourLabel.NORMAL),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "Low auth + anomaly — two red flags masked by good PDU/traffic/label. Safety floor clips to T1.",
            "difficulty": "hard",
        },
        {
            "summary": _summary_dict(AuthStability.LOW, PduSessionStability.LOW, TrafficPattern.VOLATILE, True, BehaviourLabel.ANOMALOUS),
            "expected_tier": "T1_RESTRICTED_ACCESS",
            "reasoning": "All indicators maximally bad — blatant attack. Should be T0 or T1. Safety floor enforces T1 max.",
            "difficulty": "hard",
        },
    ]

    for i, case in enumerate(adversarial_cases, 1):
        scenarios.append(OracleScenario(
            scenario_id=f"ADVER-{i:03d}",
            category="adversarial",
            summary=case["summary"],
            expected_tier=case["expected_tier"],
            reasoning=case["reasoning"],
            difficulty=case["difficulty"],
        ))

    return scenarios


def generate_oracle_dataset() -> list[dict]:
    unambiguous = generate_unambiguous_scenarios()
    conflicting = generate_conflicting_scenarios()
    adversarial = generate_adversarial_scenarios()

    all_scenarios = unambiguous + conflicting + adversarial

    dataset = []
    for s in all_scenarios:
        dataset.append({
            "scenario_id": s.scenario_id,
            "category": s.category,
            "summary": s.summary,
            "expected_tier": s.expected_tier,
            "reasoning": s.reasoning,
            "difficulty": s.difficulty,
        })

    return dataset


def main():
    dataset = generate_oracle_dataset()

    categories = {}
    tiers = {}
    for s in dataset:
        categories[s["category"]] = categories.get(s["category"], 0) + 1
        tiers[s["expected_tier"]] = tiers.get(s["expected_tier"], 0) + 1

    print(f"Generated {len(dataset)} oracle scenarios:")
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")
    print(f"\nTier distribution:")
    for tier, count in sorted(tiers.items()):
        print(f"  {tier}: {count} ({count/len(dataset)*100:.0f}%)")

    OUTPUT_PATH.write_text(json.dumps(dataset, indent=2))
    print(f"\nWritten to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
