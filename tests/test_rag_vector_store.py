from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from network_b.rag.vector_store import StoredDocument, VectorStore


def _doc(doc_id: str, source_type: str = "policy") -> StoredDocument:
    return StoredDocument(
        doc_id=doc_id,
        source_type=source_type,
        source_id=f"src_{doc_id}",
        source_title=f"Title {doc_id}",
        content=f"content for {doc_id}",
        metadata={"x": "y"},
    )


def _orthogonal_vectors(dim: int = 8) -> list[np.ndarray]:
    eye = np.eye(dim, dtype=np.float32)
    return [eye[i] for i in range(dim)]


@pytest.mark.unit
class TestVectorStoreAdd:
    def test_add_rejects_wrong_dim(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        with pytest.raises(ValueError):
            store.add(_doc("a"), np.zeros(7, dtype=np.float32))

    def test_add_many_appends_in_order(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        vecs = _orthogonal_vectors(8)
        store.add_many([_doc("a"), _doc("b")], np.stack(vecs[:2]))
        store.add_many([_doc("c")], np.stack([vecs[2]]))
        assert store.size == 3


@pytest.mark.unit
class TestVectorStoreSearch:
    def test_search_returns_nearest_first(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        vecs = _orthogonal_vectors(8)
        store.add_many(
            [_doc("a"), _doc("b"), _doc("c")],
            np.stack(vecs[:3]),
        )
        # Query is closest to vec[1] (cosine = 1.0).
        hits = store.search(vecs[1], top_k=2)
        assert len(hits) == 2
        assert hits[0].document.doc_id == "b"
        assert hits[0].similarity == pytest.approx(1.0, rel=1e-5)

    def test_search_filters_by_source_type(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        vecs = _orthogonal_vectors(8)
        store.add_many(
            [_doc("a", "policy"), _doc("b", "principle"), _doc("c", "policy")],
            np.stack(vecs[:3]),
        )
        hits = store.search(vecs[1], top_k=3, source_type="policy")
        assert {h.document.doc_id for h in hits} == {"a", "c"}

    def test_search_min_similarity_drops_low(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        vecs = _orthogonal_vectors(8)
        store.add_many([_doc("a"), _doc("b")], np.stack(vecs[:2]))
        # vecs[0] is orthogonal to vecs[1] (sim=0), so 0.5 cutoff drops it.
        hits = store.search(vecs[0], top_k=2, min_similarity=0.5)
        assert len(hits) == 1
        assert hits[0].document.doc_id == "a"

    def test_empty_store_returns_empty(self):
        store = VectorStore(store_path=Path("/tmp/none"), dim=8)
        assert store.search(np.zeros(8, dtype=np.float32), top_k=3) == []


@pytest.mark.unit
class TestVectorStorePersistence:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = VectorStore(store_path=tmp_path / "kb", dim=4)
        vecs = _orthogonal_vectors(4)
        store.add_many(
            [_doc("a", "policy"), _doc("b", "principle"), _doc("c", "precedent")],
            np.stack(vecs[:3]),
        )
        store.save()

        loaded = VectorStore.load(tmp_path / "kb", dim=4)
        assert loaded.size == 3
        hits = loaded.search(vecs[2], top_k=1)
        assert hits[0].document.doc_id == "c"
        assert hits[0].document.metadata == {"x": "y"}

    def test_load_missing_returns_empty(self, tmp_path):
        loaded = VectorStore.load(tmp_path / "nope", dim=4)
        assert loaded.size == 0

    def test_load_dim_mismatch_raises(self, tmp_path):
        store = VectorStore(store_path=tmp_path / "kb", dim=4)
        store.add_many([_doc("a")], np.eye(4, dtype=np.float32)[:1])
        store.save()
        with pytest.raises(ValueError):
            VectorStore.load(tmp_path / "kb", dim=8)
