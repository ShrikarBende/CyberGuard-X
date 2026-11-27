"""Sentence-transformer chunk embeddings with FAISS or NumPy cosine retrieval."""
from __future__ import annotations

import hashlib
import json
import logging
import sys
import re
import time
from collections import Counter
import math
from pathlib import Path
from typing import Any

import numpy as np
from app.core.config import settings

logger = logging.getLogger(__name__)
RAG_DIR = Path(__file__).resolve().parent
KNOWLEDGE_DIR = RAG_DIR / "knowledge"
INDEX_DIR = RAG_DIR / "index"
INDEX_FILE = INDEX_DIR / "knowledge.faiss"
VECTORS_FILE = INDEX_DIR / "vectors.npy"
METADATA_FILE = INDEX_DIR / "metadata.json"

_RETRIEVER: "KnowledgeRetriever | None" = None


def _lexical_tokens(text: str) -> list[str]:
    """Tokenize while retaining ATT&CK, CVE, PowerShell, and tool identifiers."""
    return [token.lower() for token in re.findall(
        r"(?i)cve-\d{4}-\d+|t\d{4}(?:\.\d{3})?|[a-z][a-z0-9_+.-]{1,}", str(text)
    )]


def _bm25_scores(query: str, documents: list[str], k1: float = 1.5, b: float = 0.75) -> np.ndarray:
    query_terms = _lexical_tokens(query)
    tokenized = [_lexical_tokens(document) for document in documents]
    if not query_terms or not tokenized:
        return np.zeros(len(documents), dtype=np.float64)
    doc_freq = Counter(term for row in tokenized for term in set(row))
    avg_len = sum(map(len, tokenized)) / max(len(tokenized), 1)
    scores = np.zeros(len(tokenized), dtype=np.float64)
    for index, tokens in enumerate(tokenized):
        counts = Counter(tokens)
        length = len(tokens)
        for term in query_terms:
            freq = counts.get(term, 0)
            if not freq:
                continue
            idf = math.log(1.0 + (len(tokenized) - doc_freq[term] + 0.5) / (doc_freq[term] + 0.5))
            denom = freq + k1 * (1.0 - b + b * length / max(avg_len, 1.0))
            scores[index] += idf * (freq * (k1 + 1.0) / denom)
    return scores


def knowledge_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted([*KNOWLEDGE_DIR.rglob("*.md"), *KNOWLEDGE_DIR.rglob("*.json")]):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _header_and_body(text: str, path: Path) -> tuple[dict[str, str], str]:
    metadata: dict[str, str] = {"id": path.stem, "title": path.stem.replace("_", " "), "source_type": "project_doc", "source_note": ""}
    if text.startswith("---\n"):
        _, header, body = text.split("---", 2)
        for line in header.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip().strip("\"'")
        return metadata, body.lstrip()
    return metadata, text


def _word_chunks(text: str, file_id: str, title: str, source_file: str,
                 chunk_words: int, overlap_words: int) -> list[dict[str, Any]]:
    sections: list[tuple[str, str]] = []
    current_title = title
    content: list[str] = []
    for line in text.splitlines():
        heading = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if heading:
            if content:
                sections.append((current_title, " ".join(content)))
            current_title = heading.group(1).strip()
            content = []
        elif line.strip():
            content.append(line.strip())
    if content:
        sections.append((current_title, " ".join(content)))
    if not sections:
        sections = [(title, text)]

    words: list[str] = []
    word_sections: list[str] = []
    for section_title, section_text in sections:
        section_words = section_text.split()
        words.extend(section_words)
        word_sections.extend([section_title] * len(section_words))
    if not words:
        return []

    stride = max(1, chunk_words - overlap_words)
    chunks = []
    for start in range(0, len(words), stride):
        end = min(start + chunk_words, len(words))
        chunk_tokens = words[start:end]
        used_sections = list(dict.fromkeys(word_sections[start:end]))
        section_title = " / ".join(used_sections)
        chunks.append({
            "chunk_id": f"{file_id}:{len(chunks) + 1:03d}",
            "file_id": file_id,
            "source_file": source_file,
            "title": title,
            "section_title": section_title,
            "text": " ".join(chunk_tokens),
        })
        if end >= len(words):
            break
    return chunks


def load_knowledge_chunks() -> list[dict[str, Any]]:
    chunks = []
    paths = sorted([*KNOWLEDGE_DIR.rglob("*.md"), *KNOWLEDGE_DIR.rglob("*.json")])
    for path in paths:
        if path.suffix.lower() == ".json":
            document = json.loads(path.read_text(encoding="utf-8"))
            body = str(document.get("text") or document.get("content") or "")
            metadata = {"id": str(document.get("doc_id") or path.stem),
                        "title": str(document.get("title") or path.stem.replace("_", " ")),
                        "source_type": str(document.get("source_type") or "past_incident"),
                        "source_note": str(document.get("source_note") or "")}
        else:
            metadata, body = _header_and_body(path.read_text(encoding="utf-8"), path)
        source_type = metadata.get("source_type", "project_doc")
        if source_type == "mitre_attack":
            source_type = "mitre"
        if source_type not in {"mitre", "cve", "past_incident"}:
            source_type = source_type or "project_doc"
        document_chunks = _word_chunks(
            body,
            metadata["id"],
            metadata["title"],
            path.name,
            settings.RAG_CHUNK_WORDS,
            settings.RAG_CHUNK_OVERLAP_WORDS,
        )
        for chunk in document_chunks:
            chunk["doc_id"] = metadata["id"]
            chunk["source_type"] = source_type
            chunk["source_note"] = metadata.get("source_note", "")
            if metadata.get("supported_indicators"):
                chunk["supported_indicators"] = [value.strip() for value in metadata["supported_indicators"].split(",")]
        chunks.extend(document_chunks)
    return chunks


def _load_embedder(model_name: str):
    from sentence_transformers import SentenceTransformer

    # Prefer a complete cached snapshot so an offline application can still use
    # its configured Sentence Transformer model.
    try:
        from huggingface_hub import scan_cache_dir

        repo_id = model_name if "/" in model_name else f"sentence-transformers/{model_name}"
        cached_repos = [repo for repo in scan_cache_dir().repos if repo.repo_id == repo_id]
        snapshots = [
            revision.snapshot_path for repo in cached_repos for revision in repo.revisions
            if (Path(revision.snapshot_path) / "modules.json").is_file()
            and (Path(revision.snapshot_path) / "1_Pooling" / "config.json").is_file()
        ]
        if snapshots:
            return SentenceTransformer(str(snapshots[-1]), model_kwargs={"local_files_only": True})
    except Exception as exc:
        logger.debug("Could not load an offline cached embedding model: %s", exc)
    return SentenceTransformer(model_name)


class KnowledgeRetriever:
    """Search interface shared by FAISS inner-product and NumPy cosine backends."""

    def __init__(self, model_name: str | None = None, force_rebuild: bool = False):
        started = time.perf_counter()
        self.model_name = model_name or settings.EMBEDDING_MODEL
        self.knowledge_hash = knowledge_hash()
        self.chunks = load_knowledge_chunks()
        if not self.chunks:
            raise RuntimeError(f"No markdown knowledge chunks found under {KNOWLEDGE_DIR}")
        self.embedder = _load_embedder(self.model_name)
        self.min_relevance_score = float(settings.RAG_MIN_RETRIEVAL_SCORE)
        self.rag_backend = str(settings.RAG_BACKEND).lower()
        self.backend = "numpy"
        self.index = None
        self.vectors: np.ndarray

        metadata = None
        if not force_rebuild and METADATA_FILE.is_file():
            try:
                metadata = json.loads(METADATA_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metadata = None
        if (metadata and VECTORS_FILE.is_file()
                and metadata.get("knowledge_hash") == self.knowledge_hash
                and metadata.get("model_name") == self.model_name
                and len(metadata.get("chunks", [])) == len(self.chunks)):
            self.chunks = metadata["chunks"]
            self.vectors = np.load(VECTORS_FILE).astype(np.float32, copy=False)
            if self._faiss_allowed() and metadata.get("backend") == "faiss" and INDEX_FILE.is_file():
                try:
                    import faiss
                    self.index = faiss.read_index(str(INDEX_FILE))
                    self.backend = "faiss"
                except Exception as exc:
                    logger.warning("FAISS index could not be loaded; using NumPy cosine search: %s", exc)
        else:
            texts = [chunk["text"] for chunk in self.chunks]
            vectors = self.embedder.encode(texts, convert_to_numpy=True, show_progress_bar=False,
                                           normalize_embeddings=True).astype(np.float32)
            self.vectors = np.ascontiguousarray(vectors)
            self._build_backend()
            self._save()
        if self.index is None and self.backend != "faiss":
            self.backend = "numpy"
        self.build_time_seconds = time.perf_counter() - started
        logger.info("RAG index ready: backend=%s chunks=%d model=%s build_seconds=%.3f",
                    self.backend, len(self.chunks), self.model_name, self.build_time_seconds)

    def _build_backend(self):
        if not self._faiss_allowed():
            self.index = None
            self.backend = "numpy"
            return
        try:
            import faiss

            self.index = faiss.IndexFlatIP(self.vectors.shape[1])
            self.index.add(self.vectors)
            self.backend = "faiss"
        except Exception as exc:
            logger.warning("Using NumPy cosine fallback for RAG retrieval: %s", exc)
            self.index = None
            self.backend = "numpy"

    def _faiss_allowed(self) -> bool:
        if self.rag_backend == "numpy":
            return False
        if self.rag_backend == "faiss":
            return True
        return not (self.rag_backend == "auto" and sys.platform == "win32")

    def _save(self):
        INDEX_DIR.mkdir(parents=True, exist_ok=True)
        np.save(VECTORS_FILE, self.vectors)
        metadata = {
            "model_name": self.model_name,
            "knowledge_hash": self.knowledge_hash,
            "backend": self.backend,
            "chunks": self.chunks,
        }
        METADATA_FILE.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        if self.backend == "faiss" and self.index is not None:
            import faiss
            faiss.write_index(self.index, str(INDEX_FILE))

    def search(self, query: str, top_k: int | None = None,
               extra_documents: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        count = max(1, int(top_k or settings.RAG_TOP_K))
        vector = self.embedder.encode([query], convert_to_numpy=True, show_progress_bar=False,
                                      normalize_embeddings=True).astype(np.float32)
        vector = np.ascontiguousarray(vector)
        documents = list(self.chunks)
        vectors = np.asarray(self.vectors, dtype=np.float32)
        if extra_documents:
            extras = [dict(doc) for doc in extra_documents if str(doc.get("text", "")).strip()]
            if extras:
                extra_vectors = self.embedder.encode([doc["text"] for doc in extras], convert_to_numpy=True,
                                                     show_progress_bar=False, normalize_embeddings=True).astype(np.float32)
                documents.extend(extras)
                vectors = np.vstack([vectors, np.asarray(extra_vectors, dtype=np.float32)])

        # Rank dense and lexical lists independently, then combine with reciprocal-rank fusion.
        dense_scores = vectors @ vector[0]
        lexical_scores = _bm25_scores(query, [str(row.get("title", "")) + " " + str(row.get("text", "")) for row in documents])
        dense_order = np.argsort(-dense_scores, kind="mergesort")
        lexical_order = np.argsort(-lexical_scores, kind="mergesort")
        dense_ranks = np.empty(len(documents), dtype=np.int64)
        dense_ranks[dense_order] = np.arange(1, len(documents) + 1)
        lexical_ranks = np.full(len(documents), len(documents) + 1, dtype=np.int64)
        lexical_positive = lexical_order[lexical_scores[lexical_order] > 0]
        lexical_ranks[lexical_positive] = np.arange(1, len(lexical_positive) + 1)
        rrf_scores = 1.0 / (60.0 + dense_ranks)
        has_lexical = lexical_scores > 0
        rrf_scores[has_lexical] += 1.0 / (60.0 + lexical_ranks[has_lexical])
        query_terms = set(_lexical_tokens(query))
        lexical_overlap = np.asarray([
            len(query_terms.intersection(_lexical_tokens(str(row.get("title", "")) + " " + str(row.get("text", "")))))
            / max(len(query_terms), 1) for row in documents
        ], dtype=np.float64)
        dense_relevance = np.clip((dense_scores + 1.0) / 2.0, 0.0, 1.0)
        rerank_scores = 0.55 * dense_relevance + 0.45 * lexical_overlap
        # A small RRF contribution preserves complementarity while overlap/cosine
        # reranking gives exact technique identifiers and tool names useful weight.
        rrf_norm = rrf_scores / max(float(rrf_scores.max()), 1e-12)
        final_scores = 0.75 * rerank_scores + 0.25 * rrf_norm
        ordered = sorted(range(len(documents)), key=lambda idx: (-final_scores[idx], -rrf_scores[idx], idx))
        results = []
        for index in ordered:
            relevance = float(final_scores[index])
            if relevance < self.min_relevance_score:
                continue
            item = {**documents[index], "score": float(dense_scores[index]),
                    "relevance_score": relevance, "rrf_score": float(rrf_scores[index]),
                    "bm25_score": float(lexical_scores[index]), "dense_rank": int(dense_ranks[index]),
                    "lexical_rank": None if not has_lexical[index] else int(lexical_ranks[index])}
            item.setdefault("doc_id", item.get("file_id", item.get("chunk_id", f"doc-{index}")))
            item.setdefault("source_type", "project_doc")
            results.append(item)
            if len(results) >= count:
                break
        return results


def get_retriever(force_rebuild: bool = False) -> KnowledgeRetriever:
    global _RETRIEVER
    if _RETRIEVER is None or force_rebuild:
        _RETRIEVER = KnowledgeRetriever(force_rebuild=force_rebuild)
    return _RETRIEVER
