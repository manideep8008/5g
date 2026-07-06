"""Hierarchical retriever with adequacy loop.

Mirrors the paper's source-to-snippet progression: first query each
source type separately (policy / principle / precedent), then check
facet coverage. If coverage is insufficient, expand top-k once before
returning whatever is available. The retriever does not block on
adequacy — it surfaces it via :class:`AdequacyReport` so callers can
decide how to react.
"""

from __future__ import annotations

import functools
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from network_b.contract.summary_schema import (
    AdequacyReport,
    EvidenceBundle,
    EvidenceSnippet,
    UeBehaviouralSummary,
)
from network_b.rag.embeddings import EmbeddingClient
from network_b.rag.vector_store import SearchHit, VectorStore

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_b_policy.yaml"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class RetrieverConfig:
    enabled: bool
    store_path: Path
    top_k_policy: int
    top_k_precedent: int
    top_k_principle: int
    min_similarity: float
    max_total_snippets: int
    max_snippet_chars: int
    min_facets: int
    expansion_factor: int


@functools.lru_cache()
def load_retriever_config(config_path: Path | None = None) -> RetrieverConfig:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    rag = cfg.get("rag") or {}
    store = rag.get("store") or {}
    retr = rag.get("retrieval") or {}
    adeq = rag.get("adequacy") or {}

    store_path_str = os.environ.get("RAG_STORE_PATH", store.get("path", "data/knowledge_base/index"))
    store_path = Path(store_path_str)
    if not store_path.is_absolute():
        store_path = _PROJECT_ROOT / store_path

    return RetrieverConfig(
        enabled=bool(rag.get("enabled", False)),
        store_path=store_path,
        top_k_policy=int(retr.get("top_k_policy", 3)),
        top_k_precedent=int(retr.get("top_k_precedent", 3)),
        top_k_principle=int(retr.get("top_k_principle", 2)),
        min_similarity=float(retr.get("min_similarity", 0.15)),
        max_total_snippets=int(retr.get("max_total_snippets", 6)),
        max_snippet_chars=int(retr.get("max_snippet_chars", 600)),
        min_facets=int(adeq.get("min_facets", 2)),
        expansion_factor=int(adeq.get("expansion_factor", 2)),
    )


def summary_to_query_text(
    summary: UeBehaviouralSummary,
    requested_slice: str,
    requested_service: str,
) -> str:
    """Render a UE summary as a natural-language query for embedding."""
    return (
        f"UE access tier decision. "
        f"auth_stability={summary.auth_stability.value}, "
        f"pdu_session_stability={summary.pdu_session_stability.value}, "
        f"traffic_pattern={summary.traffic_pattern.value}, "
        f"known_slice_usage=[{', '.join(summary.known_slice_usage)}], "
        f"recent_anomaly={str(summary.recent_anomaly).lower()}, "
        f"behaviour_label={summary.behaviour_label.value}. "
        f"Requested slice={requested_slice}, service={requested_service}."
    )


class Retriever:
    """Composes embeddings + vector store + adequacy check."""

    def __init__(
        self,
        config: RetrieverConfig,
        embedding_client: EmbeddingClient,
        store: VectorStore,
    ) -> None:
        self.config = config
        self.embedding_client = embedding_client
        self.store = store

    @classmethod
    def from_disk(
        cls,
        config: RetrieverConfig | None = None,
        embedding_client: EmbeddingClient | None = None,
    ) -> Retriever | None:
        cfg = config or load_retriever_config()
        if not cfg.enabled:
            return None
        client = embedding_client or EmbeddingClient()
        try:
            store = VectorStore.load(cfg.store_path, dim=client.config.dim)
        except (FileNotFoundError, ValueError) as exc:
            logger.warning("Vector store unavailable (%s); RAG disabled at runtime", exc)
            return None
        if store.size == 0:
            logger.warning(
                "Vector store at %s is empty; run scripts/build_knowledge_base.py first",
                cfg.store_path,
            )
            return None
        return cls(config=cfg, embedding_client=client, store=store)

    async def retrieve(
        self,
        summary: UeBehaviouralSummary,
        requested_slice: str,
        requested_service: str,
    ) -> EvidenceBundle:
        query_text = summary_to_query_text(summary, requested_slice, requested_service)
        query_vec = await self.embedding_client.embed(query_text)

        per_type_hits = self._query_per_type(query_vec, expansion=1)

        adequacy_notes: list[str] = []
        expansion_triggered = False
        distinct_facets = _count_distinct_facets(per_type_hits)

        if distinct_facets < self.config.min_facets:
            expansion_triggered = True
            adequacy_notes.append(
                f"Initial facet coverage {distinct_facets} < required {self.config.min_facets}; "
                f"expanded retrieval by factor {self.config.expansion_factor}."
            )
            per_type_hits = self._query_per_type(query_vec, expansion=self.config.expansion_factor)
            distinct_facets = _count_distinct_facets(per_type_hits)

        all_hits = _interleave(per_type_hits)
        capped = all_hits[: self.config.max_total_snippets]

        snippets = [self._hit_to_snippet(hit) for hit in capped]

        adequate = distinct_facets >= self.config.min_facets and len(snippets) > 0
        if not snippets:
            adequacy_notes.append("No snippets cleared the minimum similarity threshold.")
        if not adequate and not adequacy_notes:
            adequacy_notes.append("Evidence bundle did not meet adequacy criteria.")

        adequacy = AdequacyReport(
            facet_coverage={k: len(v) for k, v in per_type_hits.items()},
            distinct_facets=distinct_facets,
            min_facets_required=self.config.min_facets,
            adequate=adequate,
            expansion_triggered=expansion_triggered,
            notes=adequacy_notes,
        )

        return EvidenceBundle(
            bundle_id=str(uuid.uuid4()),
            retrieved_at=datetime.now(timezone.utc),
            query_text=query_text,
            snippets=snippets,
            adequacy=adequacy,
        )

    # ---- internals -----------------------------------------------------

    def _query_per_type(
        self,
        query_vec,  # np.ndarray
        expansion: int,
    ) -> dict[str, list[SearchHit]]:
        return {
            "policy": self.store.search(
                query_vec,
                top_k=self.config.top_k_policy * expansion,
                source_type="policy",
                min_similarity=self.config.min_similarity,
            ),
            "principle": self.store.search(
                query_vec,
                top_k=self.config.top_k_principle * expansion,
                source_type="principle",
                min_similarity=self.config.min_similarity,
            ),
            "precedent": self.store.search(
                query_vec,
                top_k=self.config.top_k_precedent * expansion,
                source_type="precedent",
                min_similarity=self.config.min_similarity,
            ),
        }

    def _hit_to_snippet(self, hit: SearchHit) -> EvidenceSnippet:
        content = hit.document.content
        if len(content) > self.config.max_snippet_chars:
            content = content[: self.config.max_snippet_chars].rstrip() + "…"
        return EvidenceSnippet(
            snippet_id=hit.document.doc_id,
            source_type=hit.document.source_type,  # type: ignore[arg-type]
            source_id=hit.document.source_id,
            source_title=hit.document.source_title,
            content=content,
            similarity=round(hit.similarity, 4),
            metadata=hit.document.metadata,
        )


# ---- helpers -----------------------------------------------------------


def _count_distinct_facets(per_type_hits: dict[str, list[SearchHit]]) -> int:
    return sum(1 for hits in per_type_hits.values() if hits)


def _interleave(per_type_hits: dict[str, list[SearchHit]]) -> list[SearchHit]:
    """Round-robin merge so the bundle always shows mixed source types."""
    order = ["policy", "principle", "precedent"]
    queues = {k: list(per_type_hits.get(k, [])) for k in order}
    merged: list[SearchHit] = []
    while any(queues.values()):
        for key in order:
            if queues[key]:
                merged.append(queues[key].pop(0))
    return merged
