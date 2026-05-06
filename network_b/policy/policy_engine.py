from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from network_a.summary.summary_schema import (
    PolicyEngineMetadata,
    Tier,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import LlmConfig, LlmProposal, call_llm, load_llm_config
from network_b.policy.risk_score import compute_risk_score
from network_b.policy.tier_mapper import apply_safety_floor, risk_to_max_tier

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_b_policy.yaml"


@dataclass(frozen=True)
class PolicyDecision:
    tier: Tier
    risk_score: float
    reason: str
    metadata: PolicyEngineMetadata


def _load_policy_mode(config_path: Path | None = None) -> str:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f)
    return cfg.get("policy", {}).get("mode", "rules_only")


def decide(summary: UeBehaviouralSummary) -> PolicyDecision:
    risk = compute_risk_score(summary)
    deterministic_tier = risk_to_max_tier(risk)
    final_tier, clipped, clip_reason = apply_safety_floor(deterministic_tier, summary)

    if clipped:
        reason = f"Safety floor applied: {clip_reason}"
    else:
        reason = f"Risk score {risk:.2f} maps to {final_tier.value}"

    metadata = PolicyEngineMetadata(
        llm_model_id="rules_only",
        llm_temperature=0.0,
        llm_proposed_tier=None,
        safety_floor_clipped=clipped,
        safety_floor_reason=clip_reason,
        deterministic_max_tier=deterministic_tier.value,
    )

    return PolicyDecision(
        tier=final_tier,
        risk_score=risk,
        reason=reason,
        metadata=metadata,
    )


async def decide_hybrid(
    summary: UeBehaviouralSummary,
    llm_config: LlmConfig | None = None,
    requested_slice: str = "eMBB",
    requested_service: str = "standard_data",
) -> PolicyDecision:
    risk = compute_risk_score(summary)
    deterministic_tier = risk_to_max_tier(risk)

    cfg = llm_config or load_llm_config()
    proposal = await call_llm(
        summary,
        config=cfg,
        requested_slice=requested_slice,
        requested_service=requested_service,
    )

    if proposal is None:
        logger.warning("LLM unavailable, falling back to rules-only")
        return decide(summary)

    proposed_tier = proposal.proposed_tier
    final_tier, clipped, clip_reason = apply_safety_floor(proposed_tier, summary)

    if clipped:
        reason = f"LLM proposed {proposed_tier.value} ({proposal.reasoning}), but safety floor applied: {clip_reason}"
    else:
        reason = f"LLM decided {final_tier.value}: {proposal.reasoning}"

    metadata = PolicyEngineMetadata(
        llm_model_id=cfg.model,
        llm_temperature=cfg.temperature,
        llm_proposed_tier=proposed_tier.value,
        safety_floor_clipped=clipped,
        safety_floor_reason=clip_reason,
        deterministic_max_tier=deterministic_tier.value,
    )

    return PolicyDecision(
        tier=final_tier,
        risk_score=risk,
        reason=reason,
        metadata=metadata,
    )


async def decide_auto(
    summary: UeBehaviouralSummary,
    config_path: Path | None = None,
    llm_config: LlmConfig | None = None,
    requested_slice: str = "eMBB",
    requested_service: str = "standard_data",
) -> PolicyDecision:
    mode = _load_policy_mode(config_path)

    if mode == "hybrid":
        return await decide_hybrid(
            summary,
            llm_config=llm_config,
            requested_slice=requested_slice,
            requested_service=requested_service,
        )

    return decide(summary)
