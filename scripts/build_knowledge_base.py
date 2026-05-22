"""(Re)build the RAG vector store from policy + seed docs + precedents.

Usage:
    python -m scripts.build_knowledge_base
    python -m scripts.build_knowledge_base --output data/knowledge_base/index
    python -m scripts.build_knowledge_base --no-precedents

The script is idempotent — running it overwrites the existing index.
Embeddings come from Ollama (`nomic-embed-text` by default). If Ollama
is unreachable, the embedding client transparently falls back to a
deterministic hashing-trick vector and logs a warning.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections import Counter
from pathlib import Path

# Project root on sys.path so `python scripts/build_knowledge_base.py`
# works in addition to `python -m scripts.build_knowledge_base`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from network_b.rag.embeddings import EmbeddingClient, load_embedding_config  # noqa: E402
from network_b.rag.knowledge_base import (  # noqa: E402
    load_kb_documents,
    load_policy_documents,
    load_precedent_documents,
    load_principle_documents,
)
from network_b.rag.retriever import load_retriever_config  # noqa: E402
from network_b.rag.vector_store import VectorStore  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("build_knowledge_base")

_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Override vector-store output path (default: from config).",
    )
    parser.add_argument(
        "--no-precedents",
        action="store_true",
        help="Skip indexing past access decisions.",
    )
    parser.add_argument(
        "--no-principles",
        action="store_true",
        help="Skip indexing Markdown seed docs.",
    )
    parser.add_argument(
        "--no-policy",
        action="store_true",
        help="Skip indexing policy YAML clauses.",
    )
    return parser.parse_args()


async def _build(args: argparse.Namespace) -> int:
    retriever_cfg = load_retriever_config()
    embed_cfg = load_embedding_config()
    output_path = args.output or retriever_cfg.store_path
    if not output_path.is_absolute():
        output_path = _PROJECT_ROOT / output_path

    client = EmbeddingClient(embed_cfg)

    if any([args.no_policy, args.no_principles, args.no_precedents]):
        documents = []
        if not args.no_policy:
            documents.extend(load_policy_documents(_PROJECT_ROOT / "config" / "network_b_policy.yaml"))
        if not args.no_principles:
            documents.extend(load_principle_documents(_PROJECT_ROOT / "data" / "knowledge_base" / "seed_docs"))
        if not args.no_precedents:
            documents.extend(
                load_precedent_documents(
                    _PROJECT_ROOT / "data" / "access_decisions",
                    max_count=1000,
                    max_age_days=90,
                )
            )
    else:
        documents = load_kb_documents()

    if not documents:
        logger.error("No documents found to index; aborting.")
        return 1

    counts = Counter(doc.source_type for doc in documents)
    logger.info(
        "Indexing %d documents (policy=%d, principle=%d, precedent=%d)",
        len(documents),
        counts.get("policy", 0),
        counts.get("principle", 0),
        counts.get("precedent", 0),
    )

    texts = [doc.content for doc in documents]
    matrix = await client.embed_batch(texts)
    if client.using_fallback:
        logger.warning(
            "Embeddings produced via deterministic fallback — retrieval "
            "quality will be degraded. Start Ollama and re-run for "
            "production-grade embeddings."
        )

    store = VectorStore(store_path=output_path, dim=client.config.dim)
    store.add_many([doc.to_stored() for doc in documents], matrix)
    store.save()

    logger.info("Wrote vector store to %s (%d documents)", output_path, store.size)
    return 0


def main() -> int:
    args = _parse_args()
    return asyncio.run(_build(args))


if __name__ == "__main__":
    raise SystemExit(main())
