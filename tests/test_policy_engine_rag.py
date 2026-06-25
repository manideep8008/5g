from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest

from network_a.summary.summary_schema import (
    AdequacyReport,
    AuthStability,
    BehaviourLabel,
    EvidenceBundle,
    EvidenceSnippet,
    PduSessionStability,
    Tier,
    TrafficPattern,
    UeBehaviouralSummary,
)
from network_b.policy import llm_client as llm_client_mod
from network_b.policy import policy_engine as policy_engine_mod
from network_b.policy.llm_client import LlmConfig, LlmProposal, build_user_prompt, format_evidence_block
from network_b.policy.policy_engine import decide_hybrid
from network_b.rag.embeddings import EmbeddingClient, EmbeddingConfig
from network_b.rag.retriever import Retriever, RetrieverConfig
from network_b.rag.vector_store import StoredDocument, VectorStore


class _UniformEmbeddingClient(EmbeddingClient):
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


def _bundle_with_snippet(content: str = "policy text") -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="b-1",
        retrieved_at=datetime.now(timezone.utc),
        query_text="q",
        snippets=[
            EvidenceSnippet(
                snippet_id="p1",
                source_type="policy",
                source_id="src1",
                source_title="Safety floor rule 1",
                content=content,
                similarity=0.91,
            )
        ],
        adequacy=AdequacyReport(
            facet_coverage={"policy": 1, "principle": 0, "precedent": 0},
            distinct_facets=1,
            min_facets_required=2,
            adequate=False,
            expansion_triggered=True,
            notes=["only one facet"],
        ),
    )


@pytest.mark.unit
class TestFormatEvidenceBlock:
    def test_empty_when_no_bundle(self):
        assert format_evidence_block(None) == ""

    def test_includes_snippet_header_and_content(self):
        block = format_evidence_block(_bundle_with_snippet("never grant T3 if anomaly"))
        assert "[policy:p1]" in block
        assert "Safety floor rule 1" in block
        assert "never grant T3 if anomaly" in block
        assert "inadequate" in block.lower()  # warning rendered
        assert "expanded" in block.lower()    # expansion note rendered

    def test_build_user_prompt_includes_evidence(self):
        prompt = build_user_prompt(
            _summary(),
            "eMBB",
            "standard_data",
            evidence=_bundle_with_snippet("clause"),
        )
        assert "Retrieved Evidence" in prompt
        assert "[policy:p1]" in prompt


def _make_retriever(tmp_path: Path) -> Retriever:
    cfg = RetrieverConfig(
        enabled=True,
        store_path=tmp_path / "kb",
        top_k_policy=2,
        top_k_precedent=2,
        top_k_principle=2,
        min_similarity=0.0,
        max_total_snippets=4,
        max_snippet_chars=200,
        min_facets=2,
        expansion_factor=2,
    )
    client = _UniformEmbeddingClient(dim=16)
    store = VectorStore(store_path=cfg.store_path, dim=client.config.dim)
    # Seed three source types so adequacy is satisfied.
    docs = [
        StoredDocument("p1", "policy", "src1", "Safety floor", "anomaly clipped to T2"),
        StoredDocument("pr1", "principle", "src2", "Never trust", "treat every UE as untrusted"),
        StoredDocument("c1", "precedent", "src3", "Past UE", "anomaly + high auth → T2"),
    ]
    vecs = []
    for i in range(3):
        v = np.zeros(16, dtype=np.float32)
        v[i] = 1.0
        vecs.append(v)
    store.add_many(docs, np.stack(vecs))
    return Retriever(config=cfg, embedding_client=client, store=store)


class _StubProposal(LlmProposal):
    pass


@pytest.mark.integration
class TestDecideHybridWithRetriever:
    def test_evidence_attached_to_decision(self, tmp_path, monkeypatch):
        retr = _make_retriever(tmp_path)

        seen_evidence: dict[str, EvidenceBundle | None] = {}

        async def fake_call_llm(summary, config=None, requested_slice="eMBB",
                                requested_service="standard_data", evidence=None):
            seen_evidence["bundle"] = evidence
            return LlmProposal(
                proposed_tier=Tier.T2_MONITORED_ACCESS,
                reasoning="Anomaly flag observed; cite [policy:p1].",
                confidence=0.8,
                raw_response="{}",
            )

        monkeypatch.setattr(policy_engine_mod, "call_llm", fake_call_llm)
        monkeypatch.setattr(
            policy_engine_mod,
            "load_llm_config",
            lambda: LlmConfig("stub-model", 0.0, "http://x", 5),
        )

        decision = asyncio.run(
            decide_hybrid(
                _summary(recent_anomaly=True),
                requested_slice="eMBB",
                requested_service="standard_data",
                retriever=retr,
            )
        )

        assert decision.evidence is not None
        assert decision.evidence.adequacy.adequate is True
        assert decision.metadata.rag_enabled is True
        assert decision.metadata.rag_adequate is True
        # The LLM saw an evidence bundle.
        assert seen_evidence["bundle"] is not None
        assert len(seen_evidence["bundle"].snippets) >= 2
        # Safety floor still clips T3 → T2 if LLM had proposed T3, but here
        # LLM already proposed T2 and floor allows T2 with anomaly.
        assert decision.tier == Tier.T2_MONITORED_ACCESS

    def test_falls_back_to_rules_when_llm_fails_but_keeps_evidence(self, tmp_path, monkeypatch):
        retr = _make_retriever(tmp_path)

        async def failing_call_llm(*args, **kwargs):
            return None

        monkeypatch.setattr(policy_engine_mod, "call_llm", failing_call_llm)
        monkeypatch.setattr(
            policy_engine_mod,
            "load_llm_config",
            lambda: LlmConfig("stub-model", 0.0, "http://x", 5),
        )

        decision = asyncio.run(
            decide_hybrid(
                _summary(),
                retriever=retr,
            )
        )

        # Rules-only path was taken because the LLM was unavailable, but the
        # evidence we did retrieve is preserved on the decision for audit.
        assert decision.metadata.llm_model_id == "rules_only"
        assert decision.evidence is not None
        assert decision.evidence.adequacy.adequate is True

    def test_retriever_none_means_no_evidence(self, tmp_path, monkeypatch):
        async def fake_call_llm(summary, config=None, requested_slice="eMBB",
                                requested_service="standard_data", evidence=None):
            assert evidence is None
            return LlmProposal(
                proposed_tier=Tier.T3_FULL_ACCESS,
                reasoning="all clean",
                confidence=0.9,
                raw_response="{}",
            )

        monkeypatch.setattr(policy_engine_mod, "call_llm", fake_call_llm)
        monkeypatch.setattr(
            policy_engine_mod,
            "load_llm_config",
            lambda: LlmConfig("stub", 0.0, "http://x", 5),
        )

        decision = asyncio.run(decide_hybrid(_summary(), retriever=None))
        assert decision.evidence is None
        assert decision.metadata.rag_enabled is False
        assert decision.metadata.rag_adequate is None
