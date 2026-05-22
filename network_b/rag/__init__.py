"""Retrieval-Augmented Generation layer for Network B's policy engine.

Grounds LLM tier decisions in retrieved evidence (policy clauses, ZTA
principles, historical precedents) rather than relying on parametric
memory alone. Inspired by the evidence-grounded dynamic hierarchical RAG
reference architecture for intent-driven network management
(Lai et al., IEEE Commun. Mag., 2026).
"""

from network_b.rag.embeddings import EmbeddingClient, EmbeddingConfig, load_embedding_config
from network_b.rag.knowledge_base import KbDocument, load_kb_documents
from network_b.rag.retriever import Retriever, RetrieverConfig, load_retriever_config
from network_b.rag.vector_store import VectorStore

__all__ = [
    "EmbeddingClient",
    "EmbeddingConfig",
    "KbDocument",
    "Retriever",
    "RetrieverConfig",
    "VectorStore",
    "load_embedding_config",
    "load_kb_documents",
    "load_retriever_config",
]
