"""Knowledge base loaders.

Three source types feed the RAG layer:

  * ``policy``     — clauses extracted from ``config/network_b_policy.yaml``
                    (risk weights, tier thresholds, safety floor rules,
                    enforcement). These are authoritative for tier
                    decisions.
  * ``principle``  — Zero Trust narrative documents under
                    ``data/knowledge_base/seed_docs/``. Markdown sections
                    are split on H2 headings.
  * ``precedent``  — historical ``AccessDecision`` JSON files in
                    ``data/access_decisions/``. Each becomes a short text
                    rendering of "summary -> tier (reason)" so the LLM can
                    learn from past resolutions.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import yaml

from network_b.rag.vector_store import StoredDocument

logger = logging.getLogger(__name__)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_POLICY_YAML = _PROJECT_ROOT / "config" / "network_b_policy.yaml"
_SEED_DOCS_DIR = _PROJECT_ROOT / "data" / "knowledge_base" / "seed_docs"
_ACCESS_DECISIONS_DIR = _PROJECT_ROOT / "data" / "access_decisions"

_H2_SPLIT = re.compile(r"^##\s+", re.MULTILINE)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


@dataclass(frozen=True)
class KbDocument:
    """An indexed knowledge-base entry awaiting embedding."""

    doc_id: str
    source_type: str  # "policy" | "principle" | "precedent"
    source_id: str
    source_title: str
    content: str
    metadata: dict[str, str] = field(default_factory=dict)

    def to_stored(self) -> StoredDocument:
        return StoredDocument(
            doc_id=self.doc_id,
            source_type=self.source_type,
            source_id=self.source_id,
            source_title=self.source_title,
            content=self.content,
            metadata=self.metadata,
        )


# ---- public API --------------------------------------------------------


def load_kb_documents(
    policy_yaml: Path | None = None,
    seed_docs_dir: Path | None = None,
    access_decisions_dir: Path | None = None,
    max_precedents: int = 1000,
    max_precedent_age_days: int = 90,
) -> list[KbDocument]:
    """Build the full corpus from policy + seed docs + recent precedents."""
    docs: list[KbDocument] = []
    docs.extend(load_policy_documents(policy_yaml or _POLICY_YAML))
    docs.extend(load_principle_documents(seed_docs_dir or _SEED_DOCS_DIR))
    docs.extend(
        load_precedent_documents(
            access_decisions_dir or _ACCESS_DECISIONS_DIR,
            max_count=max_precedents,
            max_age_days=max_precedent_age_days,
        )
    )
    logger.info("KB load: %d documents total", len(docs))
    return docs


def load_policy_documents(policy_yaml: Path) -> list[KbDocument]:
    if not policy_yaml.exists():
        logger.warning("Policy YAML not found at %s", policy_yaml)
        return []
    with open(policy_yaml) as f:
        cfg = yaml.safe_load(f) or {}

    docs: list[KbDocument] = []
    source_id = policy_yaml.name

    # Risk weights — explain how the deterministic score is computed.
    risk_weights = cfg.get("risk_weights") or {}
    if risk_weights:
        weight_lines = [f"  - {k}: {v}" for k, v in risk_weights.items()]
        content = (
            "Risk-score weights used by the deterministic policy layer. "
            "Each summary feature contributes a weighted partial risk; the "
            "total is clamped to [0, 1].\n" + "\n".join(weight_lines)
        )
        docs.append(_make_policy_doc(source_id, "risk_weights", "Risk weights", content))

    # Tier thresholds — the deterministic ceiling.
    thresholds = cfg.get("tier_thresholds") or {}
    if thresholds:
        lines = [f"  - {tier}: {bounds}" for tier, bounds in thresholds.items()]
        content = (
            "Tier thresholds mapping risk score to the maximum allowed tier. "
            "Lower-risk requests may receive a higher tier; higher-risk "
            "requests are clipped down.\n" + "\n".join(lines)
        )
        docs.append(_make_policy_doc(source_id, "tier_thresholds", "Tier thresholds", content))

    # Safety floor — the non-negotiable hard rules.
    safety = cfg.get("safety_floor") or {}
    if safety.get("enabled") and safety.get("hard_rules"):
        for idx, rule in enumerate(safety["hard_rules"]):
            cond = rule.get("condition", "")
            max_tier = rule.get("max_tier", "")
            content = (
                f"Safety-floor hard rule {idx + 1}: when `{cond}` holds, the "
                f"final tier MUST NOT exceed {max_tier}. This clip applies "
                "even when the LLM proposes a higher tier."
            )
            docs.append(
                _make_policy_doc(
                    source_id,
                    f"safety_floor_rule_{idx + 1}",
                    f"Safety floor rule {idx + 1}",
                    content,
                    metadata={"condition": str(cond), "max_tier": str(max_tier)},
                )
            )

    return docs


def load_principle_documents(seed_docs_dir: Path) -> list[KbDocument]:
    if not seed_docs_dir.exists():
        logger.info("No seed-docs dir at %s; skipping principle docs", seed_docs_dir)
        return []

    docs: list[KbDocument] = []
    for md_path in sorted(seed_docs_dir.glob("*.md")):
        text = md_path.read_text(encoding="utf-8")
        for section_title, section_body in _split_markdown_sections(text):
            content = _sanitize(section_body).strip()
            if not content:
                continue
            docs.append(
                KbDocument(
                    doc_id=_stable_id("principle", md_path.name, section_title),
                    source_type="principle",
                    source_id=md_path.name,
                    source_title=section_title or md_path.stem,
                    content=content,
                    metadata={"file": md_path.name},
                )
            )
    return docs


def load_precedent_documents(
    access_decisions_dir: Path,
    max_count: int,
    max_age_days: int,
) -> list[KbDocument]:
    if not access_decisions_dir.exists():
        logger.info("No access-decisions dir at %s; skipping precedents", access_decisions_dir)
        return []

    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=max_age_days)
    files = sorted(
        access_decisions_dir.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    docs: list[KbDocument] = []
    for path in files:
        if len(docs) >= max_count:
            break
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping unreadable precedent %s: %s", path.name, exc)
            continue

        summary = data.get("summary")
        if not summary:
            # Backward-compat: older decisions don't carry the summary;
            # we cannot use them as precedents.
            continue

        decided_at = _parse_iso(data.get("decided_at"))
        if decided_at and decided_at < cutoff:
            continue

        rendered = _render_precedent(data, summary)
        if not rendered:
            continue

        docs.append(
            KbDocument(
                doc_id=_stable_id("precedent", path.name, ""),
                source_type="precedent",
                source_id=path.name,
                source_title=f"Past decision {data.get('request_id', path.stem)}",
                content=rendered,
                metadata={
                    "tier": str(data.get("final_tier", "")),
                    "decided_at": str(data.get("decided_at", "")),
                    "request_id": str(data.get("request_id", "")),
                },
            )
        )
    return docs


# ---- helpers -----------------------------------------------------------


def _make_policy_doc(
    source_id: str,
    suffix: str,
    title: str,
    content: str,
    metadata: dict[str, str] | None = None,
) -> KbDocument:
    return KbDocument(
        doc_id=_stable_id("policy", source_id, suffix),
        source_type="policy",
        source_id=source_id,
        source_title=title,
        content=_sanitize(content).strip(),
        metadata=metadata or {},
    )


def _stable_id(source_type: str, source_id: str, suffix: str) -> str:
    digest = hashlib.sha1(f"{source_type}|{source_id}|{suffix}".encode("utf-8")).hexdigest()
    return f"{source_type}_{digest[:16]}"


def _split_markdown_sections(text: str) -> Iterable[tuple[str, str]]:
    """Yield (title, body) tuples by splitting on H2 (## ) headings.

    If the document has no H2s, the whole body is yielded with the H1
    (or filename-derived) title.
    """
    parts = _H2_SPLIT.split(text)
    if len(parts) == 1:
        # No H2 — use the first H1 as the title, body is everything else.
        first_line, _, rest = text.partition("\n")
        title = first_line.lstrip("# ").strip() or "Document"
        yield title, rest.strip()
        return

    # parts[0] is the preamble before the first H2.
    preamble = parts[0]
    pre_first_line, _, pre_rest = preamble.partition("\n")
    pre_title = pre_first_line.lstrip("# ").strip() or "Preamble"
    if pre_rest.strip():
        yield pre_title, pre_rest.strip()

    for chunk in parts[1:]:
        if not chunk.strip():
            continue
        title_line, _, body = chunk.partition("\n")
        yield title_line.strip(), body.strip()


def _render_precedent(decision: dict, summary: dict) -> str:
    tier = decision.get("final_tier", "UNKNOWN")
    reason = decision.get("reason", "").strip()
    meta = decision.get("policy_engine_metadata") or {}
    clipped = bool(meta.get("safety_floor_clipped"))

    summary_line = ", ".join(
        f"{k}={v}"
        for k, v in summary.items()
        if k in {
            "auth_stability",
            "pdu_session_stability",
            "traffic_pattern",
            "recent_anomaly",
            "behaviour_label",
        }
    )

    floor_note = " (safety-floor clipped)" if clipped else ""
    content = textwrap.dedent(
        f"""\
        Past UE profile: {summary_line}
        Final tier assigned: {tier}{floor_note}
        Reasoning: {reason}
        """
    ).strip()
    return _sanitize(content)


def _parse_iso(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    try:
        # tolerate trailing Z.
        cleaned = value.replace("Z", "+00:00")
        dt = _dt.datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt


def _sanitize(text: str) -> str:
    """Strip control chars; retrieved evidence is fed into LLM prompts."""
    return _CONTROL_CHARS.sub("", text)
