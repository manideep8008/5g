from __future__ import annotations

import asyncio

import numpy as np
import pytest

from network_b.rag.embeddings import (
    EmbeddingClient,
    EmbeddingConfig,
    _hashing_trick_embed,
    _tokenize,
)


@pytest.mark.unit
class TestHashingTrick:
    def test_empty_text_returns_zeros(self):
        vec = _hashing_trick_embed("", 32)
        assert vec.shape == (32,)
        assert float(np.linalg.norm(vec)) == 0.0

    def test_deterministic_same_input(self):
        a = _hashing_trick_embed("hello world", 64)
        b = _hashing_trick_embed("hello world", 64)
        assert np.array_equal(a, b)

    def test_different_inputs_differ(self):
        a = _hashing_trick_embed("auth stability low", 64)
        b = _hashing_trick_embed("traffic pattern volatile", 64)
        assert not np.array_equal(a, b)

    def test_output_normalized(self):
        vec = _hashing_trick_embed("the quick brown fox jumps", 128)
        norm = float(np.linalg.norm(vec))
        assert norm == pytest.approx(1.0, rel=1e-5)

    def test_tokenizer_lowercases_and_splits(self):
        assert _tokenize("Hello, World! auth_stability=LOW") == [
            "hello",
            "world",
            "auth_stability",
            "low",
        ]


@pytest.mark.unit
class TestEmbeddingClientFallback:
    def _client(self) -> EmbeddingClient:
        # Point at an unreachable port so the live call fails fast and we
        # exercise the fallback path.
        cfg = EmbeddingConfig(
            model="nomic-embed-text",
            base_url="http://127.0.0.1:1",
            timeout_sec=1,
            dim=64,
        )
        return EmbeddingClient(cfg)

    def test_empty_returns_zero_vector(self):
        client = self._client()
        vec = asyncio.run(client.embed(""))
        assert vec.shape == (64,)
        assert float(np.linalg.norm(vec)) == 0.0

    def test_fallback_engages_after_failed_call(self):
        client = self._client()
        vec = asyncio.run(client.embed("UE behaviour summary"))
        assert client.using_fallback is True
        assert vec.shape == (64,)
        assert float(np.linalg.norm(vec)) == pytest.approx(1.0, rel=1e-5)

    def test_batch_shape(self):
        client = self._client()
        matrix = asyncio.run(client.embed_batch(["a b c", "d e f", "g h i"]))
        assert matrix.shape == (3, 64)
