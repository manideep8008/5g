from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

from network_a.summary.summary_schema import EvidenceBundle, Tier, UeBehaviouralSummary

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_b_policy.yaml"

SYSTEM_PROMPT = """\
You are a Zero Trust access-tier decision engine for a private 5G network.

Given a UE behavioural summary (categorical labels only — no raw data), decide \
which access tier to grant. You MUST respond with valid JSON matching the schema below.

Tiers (from most restrictive to least):
- T0_REJECT: Block access entirely. Use when behaviour is clearly malicious or highly anomalous.
- T1_RESTRICTED_ACCESS: Severely limited access. Use when multiple risk indicators are elevated.
- T2_MONITORED_ACCESS: Allow with active monitoring. Use when some indicators warrant caution.
- T3_FULL_ACCESS: Normal access. Use when all indicators are stable and trustworthy.

Decision principles:
1. A single anomaly flag alone warrants at most T2.
2. Multiple elevated risk indicators should push toward T1 or T0.
3. All-stable indicators with no anomaly justify T3.
4. When in doubt, be conservative — it is safer to restrict and re-evaluate.

Response JSON schema:
{
  "proposed_tier": "T0_REJECT | T1_RESTRICTED_ACCESS | T2_MONITORED_ACCESS | T3_FULL_ACCESS",
  "reasoning": "One sentence explaining why this tier was chosen.",
  "confidence": 0.0 to 1.0
}
"""

USER_PROMPT_TEMPLATE = """\
UE Behavioural Summary:
- auth_stability: {auth_stability}
- pdu_session_stability: {pdu_session_stability}
- traffic_pattern: {traffic_pattern}
- known_slice_usage: {known_slice_usage}
- recent_anomaly: {recent_anomaly}
- behaviour_label: {behaviour_label}

Requested access: slice={requested_slice}, service={requested_service}
{evidence_block}
Decide the access tier. Ground your reasoning in the retrieved evidence \
above when it is present, and cite snippet ids in the form [policy:id], \
[principle:id], or [precedent:id] inside the reasoning field. Respond with \
JSON only.
"""

_EVIDENCE_HEADER = "\nRetrieved Evidence (use this to ground your decision):\n"


@dataclass(frozen=True)
class LlmProposal:
    proposed_tier: Tier
    reasoning: str
    confidence: float
    raw_response: str


@dataclass(frozen=True)
class LlmConfig:
    model: str
    temperature: float
    base_url: str
    timeout_sec: int


def load_llm_config(config_path: Path | None = None) -> LlmConfig:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f)
    llm = cfg["llm"]
    return LlmConfig(
        model=llm["model"],
        temperature=llm["temperature"],
        base_url=os.environ.get("OLLAMA_BASE_URL", llm["base_url"]),
        timeout_sec=llm["timeout_sec"],
    )


_VALID_TIERS = {t.value for t in Tier}


def parse_llm_response(raw: str) -> LlmProposal | None:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1 or end == 0:
            return None
        try:
            data = json.loads(raw[start:end])
        except json.JSONDecodeError:
            return None

    tier_str = data.get("proposed_tier", "")
    if tier_str not in _VALID_TIERS:
        return None

    reasoning = str(data.get("reasoning", ""))
    confidence = float(data.get("confidence", 0.5))
    confidence = max(0.0, min(1.0, confidence))

    return LlmProposal(
        proposed_tier=Tier(tier_str),
        reasoning=reasoning,
        confidence=confidence,
        raw_response=raw,
    )


def format_evidence_block(bundle: EvidenceBundle | None) -> str:
    if bundle is None or not bundle.snippets:
        return ""

    lines: list[str] = [_EVIDENCE_HEADER]
    for snippet in bundle.snippets:
        # Untrusted retrieved text is fenced and labelled so the LLM treats
        # it as evidence rather than as instructions to follow.
        header = (
            f"[{snippet.source_type}:{snippet.snippet_id}] "
            f"{snippet.source_title} (similarity={snippet.similarity:.2f})"
        )
        lines.append(header)
        lines.append("\"\"\"")
        lines.append(snippet.content)
        lines.append("\"\"\"")
        lines.append("")

    if bundle.adequacy.expansion_triggered:
        lines.append(
            "Note: retrieval was expanded because initial evidence did not "
            "cover enough distinct sources. Treat evidence cautiously."
        )
    if not bundle.adequacy.adequate:
        lines.append(
            "Warning: the evidence bundle was flagged as inadequate. "
            "Lean conservative if evidence does not clearly justify a tier."
        )
    return "\n".join(lines) + "\n"


def build_user_prompt(
    summary: UeBehaviouralSummary,
    requested_slice: str = "eMBB",
    requested_service: str = "standard_data",
    evidence: EvidenceBundle | None = None,
) -> str:
    return USER_PROMPT_TEMPLATE.format(
        auth_stability=summary.auth_stability.value,
        pdu_session_stability=summary.pdu_session_stability.value,
        traffic_pattern=summary.traffic_pattern.value,
        known_slice_usage=", ".join(summary.known_slice_usage),
        recent_anomaly=str(summary.recent_anomaly).lower(),
        behaviour_label=summary.behaviour_label.value,
        requested_slice=requested_slice,
        requested_service=requested_service,
        evidence_block=format_evidence_block(evidence),
    )


async def call_llm(
    summary: UeBehaviouralSummary,
    config: LlmConfig | None = None,
    requested_slice: str = "eMBB",
    requested_service: str = "standard_data",
    evidence: EvidenceBundle | None = None,
) -> LlmProposal | None:
    cfg = config or load_llm_config()
    user_prompt = build_user_prompt(
        summary,
        requested_slice,
        requested_service,
        evidence=evidence,
    )

    payload = {
        "model": cfg.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {
            "temperature": cfg.temperature,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=cfg.timeout_sec) as client:
            resp = await client.post(
                f"{cfg.base_url}/api/chat",
                json=payload,
            )
        if resp.status_code != 200:
            logger.warning("Ollama returned %d: %s", resp.status_code, resp.text[:200])
            return None

        body = resp.json()
        raw_content = body.get("message", {}).get("content", "")
        return parse_llm_response(raw_content)

    except (httpx.HTTPError, Exception) as e:
        logger.warning("LLM call failed: %s", e)
        return None
