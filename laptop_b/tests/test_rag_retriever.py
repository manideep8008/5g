from __future__ import annotations

import asyncio
from pathlib import Path

import numpy as np
import pytest

from network_b.contract.summary_schema import (
    AuthStability,
    BehaviourLabel,
    PduSessionStability,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.rag.embeddings import EmbeddingClient, EmbeddingConfig
from network_b.rag.retriever import Retriever, RetrieverConfig, summary_to_query_text
from network_b.rag.vector_store import StoredDocument, VectorStore


class _UniformEmbeddingClient(EmbeddingClient):
    """Deterministic stub: returns a uniform vector with positive overlap
    against any non-negative store vector. Keeps retriever tests free of
    hashing-trick noise."""

    def __init__(self, dim: int):
        cfg = EmbeddingConfig(model="stub", base_url="http://stub", timeout_sec=1, dim=dim)
        super().__init__(cfg)
        self._uniform = np.ones(dim, dtype=np.float32) / np.sqrt(dim)

    async def embed(self, text: str) -> np.ndarray:  # type: ignore[override]
        if not text.strip():
            return np.zeros(self.config.dim, dtype=np.float32)
        return self._uniform.copy()


def _summary(**overrides) -> UeBehaviouralSummary:
    defaults = {
        "auth_stability": AuthStability.HIGH,
        "pdu_session_stability": PduSessionStability.HIGH,
        "traffic_pattern": TrafficPattern.STABLE,
        "known_slice_usage": ["eMBB"],
        "recent_anomaly": False,
        "behaviour_label": BehaviourLabel.NORMAL,
    }
    defaults.update(overrides)
    return UeBehaviouralSummary(**defaults)


def _make_retriever(tmp_path: Path, *, min_facets: int = 2) -> Retriever:
    cfg = RetrieverConfig(
        enabled=True,
        store_path=tmp_path / "kb",
        top_k_policy=2,
        top_k_precedent=2,
        top_k_principle=2,
        min_similarity=0.0,
        max_total_snippets=6,
        max_snippet_chars=200,
        min_facets=min_facets,
        expansion_factor=2,
    )
    client = _UniformEmbeddingClient(dim=32)
    store = VectorStore(store_path=cfg.store_path, dim=client.config.dim)
    return Retriever(config=cfg, embedding_client=client, store=store)


def _populate(store: VectorStore, dim: int, items: list[tuple[str, str, str]]) -> None:
    """items: list of (doc_id, source_type, content)."""
    docs = [
        StoredDocument(
            doc_id=doc_id,
            source_type=stype,
            source_id=f"src_{doc_id}",
            source_title=f"Title {doc_id}",
            content=content,
        )
        for doc_id, stype, content in items
    ]
    # Distinct orthogonal-ish vectors so each item is uniquely retrievable.
    vectors = []
    for i, _ in enumerate(items):
        v = np.zeros(dim, dtype=np.float32)
        v[i % dim] = 1.0
        vectors.append(v)
    store.add_many(docs, np.stack(vectors))


@pytest.mark.unit
class TestQueryRendering:
    def test_summary_to_query_text_includes_all_fields(self):
        text = summary_to_query_text(_summary(recent_anomaly=True), "URLLC", "voice")
        assert "auth_stability=high" in text
        assert "recent_anomaly=true" in text
        assert "URLLC" in text and "voice" in text


@pytest.mark.unit
class TestRetrieve:
    def test_returns_empty_bundle_when_store_empty(self, tmp_path):
        retr = _make_retriever(tmp_path)
        bundle = asyncio.run(
            retr.retrieve(_summary(), requested_slice="eMBB", requested_service="standard_data")
        )
        assert bundle.snippets == []
        assert bundle.adequacy.adequate is False
        assert bundle.adequacy.distinct_facets == 0

    def test_adequate_when_two_source_types_present(self, tmp_path):
        retr = _make_retriever(tmp_path, min_facets=2)
        _populate(
            retr.store,
            retr.embedding_client.config.dim,
            [
                ("p1", "policy", "safety floor rule"),
                ("pr1", "principle", "never trust by default"),
                ("c1", "precedent", "past UE with anomaly was T2"),
            ],
        )
        bundle = asyncio.run(
            retr.retrieve(_summary(recent_anomaly=True), "eMBB", "standard_data")
        )
        assert bundle.adequacy.adequate is True
        assert bundle.adequacy.distinct_facets >= 2
        source_types = {s.source_type for s in bundle.snippets}
        # Round-robin interleave should surface all three when capacity allows.
        assert source_types == {"policy", "principle", "precedent"}

    def test_expansion_triggered_when_single_facet(self, tmp_path):
        retr = _make_retriever(tmp_path, min_facets=2)
        # Only policy docs available — single facet.
        _populate(
            retr.store,
            retr.embedding_client.config.dim,
            [("p1", "policy", "weights"), ("p2", "policy", "thresholds")],
        )
        bundle = asyncio.run(retr.retrieve(_summary(), "eMBB", "standard_data"))
        assert bundle.adequacy.expansion_triggered is True
        assert bundle.adequacy.adequate is False
        assert bundle.adequacy.facet_coverage["principle"] == 0
        assert bundle.adequacy.facet_coverage["precedent"] == 0

    def test_max_total_snippets_caps_bundle(self, tmp_path):
        retr = _make_retriever(tmp_path)
        items = [(f"p{i}", "policy", f"policy snippet {i}") for i in range(10)]
        items += [(f"pr{i}", "principle", f"principle {i}") for i in range(10)]
        _populate(retr.store, retr.embedding_client.config.dim, items)
        bundle = asyncio.run(retr.retrieve(_summary(), "eMBB", "standard_data"))
        assert len(bundle.snippets) <= retr.config.max_total_snippets

    def test_long_content_truncated(self, tmp_path):
        retr = _make_retriever(tmp_path)
        long_content = "x" * 5000
        _populate(
            retr.store,
            retr.embedding_client.config.dim,
            [("p1", "policy", long_content), ("pr1", "principle", "short")],
        )
        bundle = asyncio.run(retr.retrieve(_summary(), "eMBB", "standard_data"))
        for snippet in bundle.snippets:
            assert len(snippet.content) <= retr.config.max_snippet_chars + 1


@pytest.mark.unit
class TestRetrieverFromDisk:
    def test_disabled_config_returns_none(self, tmp_path):
        cfg = RetrieverConfig(
            enabled=False,
            store_path=tmp_path,
            top_k_policy=1,
            top_k_precedent=1,
            top_k_principle=1,
            min_similarity=0.0,
            max_total_snippets=3,
            max_snippet_chars=200,
            min_facets=1,
            expansion_factor=2,
        )
        assert Retriever.from_disk(config=cfg) is None

    def test_empty_store_returns_none(self, tmp_path):
        cfg = RetrieverConfig(
            enabled=True,
            store_path=tmp_path / "kb",
            top_k_policy=1,
            top_k_precedent=1,
            top_k_principle=1,
            min_similarity=0.0,
            max_total_snippets=3,
            max_snippet_chars=200,
            min_facets=1,
            expansion_factor=2,
        )
        client = EmbeddingClient(
            EmbeddingConfig(model="x", base_url="http://127.0.0.1:1", timeout_sec=1, dim=8)
        )
        assert Retriever.from_disk(config=cfg, embedding_client=client) is None
