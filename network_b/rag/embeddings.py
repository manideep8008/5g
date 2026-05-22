"""Embedding client for the RAG layer.

Calls Ollama's /api/embeddings endpoint for high-quality text embeddings.
Falls back to a deterministic hashing-trick vector when Ollama is
unreachable or the embedding model is missing — this keeps tests and
offline development working without an external service.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

import httpx
import numpy as np
import yaml

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "network_b_policy.yaml"
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_]+")


@dataclass(frozen=True)
class EmbeddingConfig:
    model: str
    base_url: str
    timeout_sec: int
    dim: int


def load_embedding_config(config_path: Path | None = None) -> EmbeddingConfig:
    path = config_path or _CONFIG_PATH
    with open(path) as f:
        cfg = yaml.safe_load(f)
    rag = cfg.get("rag", {}).get("embedding", {})
    return EmbeddingConfig(
        model=rag.get("model", "nomic-embed-text"),
        base_url=os.environ.get("OLLAMA_BASE_URL", rag.get("base_url", "http://localhost:11434")),
        timeout_sec=int(rag.get("timeout_sec", 15)),
        dim=int(rag.get("dim", 768)),
    )


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_PATTERN.findall(text)]


def _hashing_trick_embed(text: str, dim: int) -> np.ndarray:
    """Zero-dependency deterministic fallback embedding.

    Buckets tokens into a fixed-size vector via SHA-256. Quality is poor
    compared with a learned model, but it is reproducible, fast, and
    offline. Used only when Ollama is unavailable so that the rest of the
    pipeline (vector store, retriever, adequacy loop) remains testable.
    """
    vec = np.zeros(dim, dtype=np.float32)
    tokens = _tokenize(text)
    if not tokens:
        return vec
    for tok in tokens:
        digest = hashlib.sha256(tok.encode("utf-8")).digest()
        # Use first 4 bytes for bucket, next byte's MSB for sign.
        bucket = int.from_bytes(digest[:4], "big") % dim
        sign = 1.0 if digest[4] & 0x80 else -1.0
        vec[bucket] += sign
    norm = float(np.linalg.norm(vec))
    if norm > 0:
        vec = vec / norm
    return vec


def _l2_normalize(vec: np.ndarray) -> np.ndarray:
    norm = float(np.linalg.norm(vec))
    if not math.isfinite(norm) or norm == 0.0:
        return vec
    return vec / norm


class EmbeddingClient:
    """Thin wrapper around Ollama's embedding endpoint with offline fallback."""

    def __init__(self, config: EmbeddingConfig | None = None) -> None:
        self.config = config or load_embedding_config()
        self._fallback_active = False

    @property
    def using_fallback(self) -> bool:
        return self._fallback_active

    async def embed(self, text: str) -> np.ndarray:
        if not text or not text.strip():
            return np.zeros(self.config.dim, dtype=np.float32)

        if self._fallback_active:
            return _hashing_trick_embed(text, self.config.dim)

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_sec) as client:
                resp = await client.post(
                    f"{self.config.base_url}/api/embeddings",
                    json={"model": self.config.model, "prompt": text},
                )
            if resp.status_code != 200:
                logger.warning(
                    "Ollama embeddings returned %d, switching to deterministic fallback",
                    resp.status_code,
                )
                self._fallback_active = True
                return _hashing_trick_embed(text, self.config.dim)

            data = resp.json()
            embedding = data.get("embedding")
            if not isinstance(embedding, list) or not embedding:
                logger.warning("Ollama embeddings returned empty payload, using fallback")
                self._fallback_active = True
                return _hashing_trick_embed(text, self.config.dim)

            vec = np.asarray(embedding, dtype=np.float32)
            return _l2_normalize(vec)

        except (httpx.HTTPError, OSError) as exc:
            logger.warning("Embedding call failed (%s); using deterministic fallback", exc)
            self._fallback_active = True
            return _hashing_trick_embed(text, self.config.dim)

    async def embed_batch(self, texts: list[str]) -> np.ndarray:
        """Embed a list of texts. Returns an (N, dim) matrix."""
        if not texts:
            return np.zeros((0, self.config.dim), dtype=np.float32)
        vectors = [await self.embed(t) for t in texts]
        return np.stack(vectors, axis=0)
