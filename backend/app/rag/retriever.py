"""Hybrid lexical/dense retrieval entry point.

The historical module name `indexer` remains the implementation home so saved
FAISS/NumPy indexes and existing imports stay backward compatible.
"""

from app.rag.indexer import KnowledgeRetriever, get_retriever

__all__ = ["KnowledgeRetriever", "get_retriever"]
