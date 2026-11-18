"""Sentence-transformer chunk embeddings with FAISS or NumPy cosine retrieval."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
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


def knowledge_hash() -> str:
    digest = hashlib.sha256()
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
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
    for path in sorted(KNOWLEDGE_DIR.glob("*.md")):
        metadata, body = _header_and_body(path.read_text(encoding="utf-8"), path)
        chunks.extend(_word_chunks(
            body,
            metadata["id"],
            metadata["title"],
            path.name,
            settings.RAG_CHUNK_WORDS,
            settings.RAG_CHUNK_OVERLAP_WORDS,
        ))
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
            if metadata.get("backend") == "faiss" and INDEX_FILE.is_file():
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
        try:
            import faiss

            self.index = faiss.IndexFlatIP(self.vectors.shape[1])
            self.index.add(self.vectors)
            self.backend = "faiss"
        except Exception as exc:
            logger.warning("Using NumPy cosine fallback for RAG retrieval: %s", exc)
            self.index = None
            self.backend = "numpy"

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

    def search(self, query: str, top_k: int | None = None) -> list[dict[str, Any]]:
        count = min(max(1, int(top_k or settings.RAG_TOP_K)), len(self.chunks))
        vector = self.embedder.encode([query], convert_to_numpy=True, show_progress_bar=False,
                                      normalize_embeddings=True).astype(np.float32)
        vector = np.ascontiguousarray(vector)
        if self.backend == "faiss" and self.index is not None:
            scores, indices = self.index.search(vector, count)
            pairs = zip(indices[0].tolist(), scores[0].tolist())
        else:
            scores = self.vectors @ vector[0]
            indices = np.argsort(scores)[::-1][:count]
            pairs = ((int(index), float(scores[index])) for index in indices)
        return [
            {**self.chunks[index], "score": float(score)}
            for index, score in pairs if index >= 0
        ]


def get_retriever(force_rebuild: bool = False) -> KnowledgeRetriever:
    global _RETRIEVER
    if _RETRIEVER is None or force_rebuild:
        _RETRIEVER = KnowledgeRetriever(force_rebuild=force_rebuild)
    return _RETRIEVER
