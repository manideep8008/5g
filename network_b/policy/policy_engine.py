from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from pathlib import Path

import yaml

from network_a.summary.summary_schema import (
    AuthStability,
    BehaviourLabel,
    EvidenceBundle,
    PduSessionStability,
    PolicyEngineMetadata,
    Tier,
    TIER_ORDER,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.policy.llm_client import LlmConfig, LlmProposal, call_llm, load_llm_config
from network_b.rag.retriever import Retriever

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_b_policy.yaml"

FIELD_RISK_MAP = {
    AuthStability.HIGH: 0.0,
    AuthStability.MEDIUM: 0.5,
    AuthStability.LOW: 1.0,
    PduSessionStability.HIGH: 0.0,
    PduSessionStability.MEDIUM: 0.5,
    PduSessionStability.LOW: 1.0,
    TrafficPattern.STABLE: 0.0,
    TrafficPattern.MODERATE: 0.5,
    TrafficPattern.VOLATILE: 1.0,
    BehaviourLabel.NORMAL: 0.0,
    BehaviourLabel.SUSPICIOUS: 0.5,
    BehaviourLabel.ANOMALOUS: 1.0,
}

DEFAULT_WEIGHTS = {
    "auth_stability": 0.25,
    "pdu_session_stability": 0.20,
    "traffic_pattern": 0.20,
    "recent_anomaly": 0.20,
    "behaviour_label": 0.15,
}


def compute_risk_score(summary: UeBehaviouralSummary) -> float:
    score = 0.0
    score += DEFAULT_WEIGHTS["auth_stability"] * FIELD_RISK_MAP[summary.auth_stability]
    score += DEFAULT_WEIGHTS["pdu_session_stability"] * FIELD_RISK_MAP[summary.pdu_session_stability]
    score += DEFAULT_WEIGHTS["traffic_pattern"] * FIELD_RISK_MAP[summary.traffic_pattern]
    score += DEFAULT_WEIGHTS["recent_anomaly"] * (1.0 if summary.recent_anomaly else 0.0)
    score += DEFAULT_WEIGHTS["behaviour_label"] * FIELD_RISK_MAP[summary.behaviour_label]
    return round(min(max(score, 0.0), 1.0), 4)


def risk_to_max_tier(risk_score: float) -> Tier:
    if risk_score <= 0.20:
        return Tier.T3_FULL_ACCESS
    if risk_score <= 0.50:
        return Tier.T2_MONITORED_ACCESS
    if risk_score <= 0.80:
        return Tier.T1_RESTRICTED_ACCESS
    return Tier.T0_REJECT


def apply_safety_floor(
    proposed_tier: Tier,
    summary: UeBehaviouralSummary,
) -> tuple[Tier, bool, str | None]:
    floor_tier = proposed_tier
    reason = None

    if summary.recent_anomaly and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T2_MONITORED_ACCESS]:
        floor_tier = Tier.T2_MONITORED_ACCESS
        reason = "recent_anomaly=true forced clip to T2"

    if summary.auth_stability == AuthStability.LOW and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor_tier = Tier.T1_RESTRICTED_ACCESS
        reason = "auth_stability=low forced clip to T1"

    if summary.behaviour_label == BehaviourLabel.ANOMALOUS and TIER_ORDER[floor_tier] > TIER_ORDER[Tier.T1_RESTRICTED_ACCESS]:
        floor_tier = Tier.T1_RESTRICTED_ACCESS
        reason = "behaviour_label=anomalous forced clip to T1"

    clipped = floor_tier != proposed_tier
    return floor_tier, clipped, reason if clipped else None


@dataclass(frozen=True)
class PolicyDecision:
    tier: Tier
    risk_score: float
    reason: str
    metadata: PolicyEngineMetadata
    evidence: EvidenceBundle | None = None


@functools.lru_cache()
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
    retriever: Retriever | None = None,
) -> PolicyDecision:
    risk = compute_risk_score(summary)
    deterministic_tier = risk_to_max_tier(risk)

    cfg = llm_config or load_llm_config()

    evidence: EvidenceBundle | None = None
    if retriever is not None:
        try:
            evidence = await retriever.retrieve(
                summary,
                requested_slice=requested_slice,
                requested_service=requested_service,
            )
        except Exception as exc:  # noqa: BLE001 — RAG is best-effort
            logger.warning("RAG retrieval failed (%s); proceeding without evidence", exc)
            evidence = None

    proposal = await call_llm(
        summary,
        config=cfg,
        requested_slice=requested_slice,
        requested_service=requested_service,
        evidence=evidence,
    )

    if proposal is None:
        logger.warning("LLM unavailable, falling back to rules-only")
        rules_decision = decide(summary)
        # Attach the evidence we did retrieve, if any — useful for audit.
        return PolicyDecision(
            tier=rules_decision.tier,
            risk_score=rules_decision.risk_score,
            reason=rules_decision.reason,
            metadata=rules_decision.metadata,
            evidence=evidence,
        )

    proposed_tier = proposal.proposed_tier
    final_tier, clipped, clip_reason = apply_safety_floor(proposed_tier, summary)

    if clipped:
        reason = (
            f"LLM proposed {proposed_tier.value} ({proposal.reasoning}), "
            f"but safety floor applied: {clip_reason}"
        )
    else:
        reason = f"LLM decided {final_tier.value}: {proposal.reasoning}"

    metadata = PolicyEngineMetadata(
        llm_model_id=cfg.model,
        llm_temperature=cfg.temperature,
        llm_proposed_tier=proposed_tier.value,
        safety_floor_clipped=clipped,
        safety_floor_reason=clip_reason,
        deterministic_max_tier=deterministic_tier.value,
        rag_enabled=evidence is not None,
        rag_adequate=evidence.adequacy.adequate if evidence is not None else None,
    )

    return PolicyDecision(
        tier=final_tier,
        risk_score=risk,
        reason=reason,
        metadata=metadata,
        evidence=evidence,
    )


async def decide_auto(
    summary: UeBehaviouralSummary,
    config_path: Path | None = None,
    llm_config: LlmConfig | None = None,
    requested_slice: str = "eMBB",
    requested_service: str = "standard_data",
    retriever: Retriever | None = None,
) -> PolicyDecision:
    mode = _load_policy_mode(config_path)

    if mode == "hybrid":
        return await decide_hybrid(
            summary,
            llm_config=llm_config,
            requested_slice=requested_slice,
            requested_service=requested_service,
            retriever=retriever,
        )

    return decide(summary)
