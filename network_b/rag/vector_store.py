"""In-memory vector store with disk persistence.

A research-prototype store: O(N) cosine similarity over normalized
float32 vectors. Adequate for thousands of documents; replace with an
indexed store (FAISS/Chroma/pgvector) before scaling beyond ~10k items.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredDocument:
    doc_id: str
    source_type: str
    source_id: str
    source_title: str
    content: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SearchHit:
    document: StoredDocument
    similarity: float


class VectorStore:
    """L2-normalized cosine-similarity vector store, persisted to disk."""

    _VECTORS_FILE = "vectors.npy"
    _DOCS_FILE = "documents.jsonl"
    _META_FILE = "meta.json"

    def __init__(self, store_path: Path, dim: int) -> None:
        self.store_path = Path(store_path)
        self.dim = dim
        self._documents: list[StoredDocument] = []
        self._vectors: np.ndarray = np.zeros((0, dim), dtype=np.float32)

    # ---- public API ----------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._documents)

    def add(self, document: StoredDocument, vector: np.ndarray) -> None:
        if vector.shape != (self.dim,):
            raise ValueError(
                f"vector dim mismatch: got {vector.shape}, expected ({self.dim},)"
            )
        normalized = _ensure_normalized(vector.astype(np.float32))
        self._documents.append(document)
        if self._vectors.shape[0] == 0:
            self._vectors = normalized.reshape(1, -1)
        else:
            self._vectors = np.vstack([self._vectors, normalized.reshape(1, -1)])

    def add_many(self, documents: list[StoredDocument], matrix: np.ndarray) -> None:
        if matrix.shape[0] != len(documents):
            raise ValueError("documents and matrix length mismatch")
        if matrix.shape[1] != self.dim:
            raise ValueError(
                f"matrix dim mismatch: got {matrix.shape[1]}, expected {self.dim}"
            )
        if not documents:
            return
        normalized = np.stack([_ensure_normalized(v.astype(np.float32)) for v in matrix])
        self._documents.extend(documents)
        if self._vectors.shape[0] == 0:
            self._vectors = normalized
        else:
            self._vectors = np.vstack([self._vectors, normalized])

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int,
        source_type: str | None = None,
        min_similarity: float = 0.0,
    ) -> list[SearchHit]:
        if self._vectors.shape[0] == 0 or top_k <= 0:
            return []

        query = _ensure_normalized(query_vector.astype(np.float32))
        sims = self._vectors @ query

        if source_type is None:
            candidate_indices = np.arange(self._vectors.shape[0])
        else:
            candidate_indices = np.array(
                [i for i, d in enumerate(self._documents) if d.source_type == source_type],
                dtype=np.int64,
            )
            if candidate_indices.size == 0:
                return []

        candidate_sims = sims[candidate_indices]
        # argpartition for top-k, then sort the candidates only.
        k = int(min(top_k, candidate_sims.size))
        partition_idx = np.argpartition(-candidate_sims, k - 1)[:k]
        top_sorted = partition_idx[np.argsort(-candidate_sims[partition_idx])]

        results: list[SearchHit] = []
        for local_idx in top_sorted:
            global_idx = int(candidate_indices[int(local_idx)])
            sim = float(candidate_sims[int(local_idx)])
            if sim < min_similarity:
                continue
            results.append(SearchHit(document=self._documents[global_idx], similarity=sim))
        return results

    def save(self) -> None:
        self.store_path.mkdir(parents=True, exist_ok=True)
        np.save(self.store_path / self._VECTORS_FILE, self._vectors)
        with open(self.store_path / self._DOCS_FILE, "w") as f:
            for doc in self._documents:
                f.write(json.dumps(_doc_to_dict(doc)) + "\n")
        meta = {"dim": self.dim, "count": len(self._documents)}
        (self.store_path / self._META_FILE).write_text(json.dumps(meta, indent=2))

    @classmethod
    def load(cls, store_path: Path, dim: int) -> VectorStore:
        store = cls(store_path=store_path, dim=dim)
        vectors_file = store.store_path / cls._VECTORS_FILE
        docs_file = store.store_path / cls._DOCS_FILE
        meta_file = store.store_path / cls._META_FILE

        if not (vectors_file.exists() and docs_file.exists() and meta_file.exists()):
            logger.info("Vector store at %s is empty or missing", store.store_path)
            return store

        meta = json.loads(meta_file.read_text())
        stored_dim = int(meta.get("dim", dim))
        if stored_dim != dim:
            raise ValueError(
                f"vector store dim mismatch: on-disk {stored_dim}, requested {dim}. "
                "Rebuild the knowledge base after changing embedding dimension."
            )

        vectors = np.load(vectors_file)
        if vectors.dtype != np.float32:
            vectors = vectors.astype(np.float32)
        documents: list[StoredDocument] = []
        with open(docs_file) as f:
            for line in f:
                if line.strip():
                    documents.append(_dict_to_doc(json.loads(line)))

        if vectors.shape[0] != len(documents):
            raise ValueError(
                f"vector store corruption: {vectors.shape[0]} vectors, {len(documents)} docs"
            )

        store._documents = documents
        store._vectors = vectors
        logger.info("Loaded vector store: %d documents", len(documents))
        return store


# ---- helpers -----------------------------------------------------------


def _ensure_normalized(vec: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vec))
    if norm <= 0.0:
        return vec
    return vec / norm


def _doc_to_dict(doc: StoredDocument) -> dict[str, Any]:
    return {
        "doc_id": doc.doc_id,
        "source_type": doc.source_type,
        "source_id": doc.source_id,
        "source_title": doc.source_title,
        "content": doc.content,
        "metadata": doc.metadata,
    }


def _dict_to_doc(data: dict[str, Any]) -> StoredDocument:
    return StoredDocument(
        doc_id=str(data["doc_id"]),
        source_type=str(data["source_type"]),
        source_id=str(data["source_id"]),
        source_title=str(data["source_title"]),
        content=str(data["content"]),
        metadata=dict(data.get("metadata") or {}),
    )
