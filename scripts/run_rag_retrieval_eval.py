"""Regenerate a RAG retrieval report from the existing test question set."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.rag.indexer import get_retriever, knowledge_hash
from ml.evaluation.output_paths import DEFAULT_RESULTS_DIR

_question_spec = importlib.util.spec_from_file_location(
    "cyberguardx_rag_questions", ROOT / "backend" / "tests" / "test_rag_retrieval.py"
)
_question_module = importlib.util.module_from_spec(_question_spec)
assert _question_spec and _question_spec.loader
_question_spec.loader.exec_module(_question_module)
RETRIEVAL_QUESTIONS = _question_module.RETRIEVAL_QUESTIONS


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-results", action="store_true", help="Write under backend/ml/evaluation/results")
    args = parser.parse_args()
    retriever = get_retriever()
    result_rows = []
    missed = []
    for item in RETRIEVAL_QUESTIONS:
        hits = retriever.search(item["question"], top_k=3)
        sources = [hit.get("source_file") for hit in hits]
        row = {
            "question": item["question"],
            "expected_source_file": item["expected_source_file"],
            "top_retrieved_source": sources[0] if sources else None,
            "hit_at_1": bool(sources and sources[0] == item["expected_source_file"]),
            "hit_at_3": item["expected_source_file"] in sources,
        }
        result_rows.append(row)
        if not row["hit_at_3"]:
            missed.append({key: row[key] for key in ("question", "expected_source_file", "top_retrieved_source")})

    count = len(result_rows)
    report = {
        "date": datetime.now(timezone.utc).date().isoformat(),
        "model_name": retriever.model_name,
        "faiss_backend": retriever.backend,
        "knowledge_file_hash": knowledge_hash(),
        "question_count": count,
        "hit_at_1": round(sum(row["hit_at_1"] for row in result_rows) / count, 4),
        "hit_at_3": round(sum(row["hit_at_3"] for row in result_rows) / count, 4),
        "missed_questions": missed,
        "questions": result_rows,
    }
    out_dir = DEFAULT_RESULTS_DIR if args.write_results else Path(tempfile.gettempdir()) / "cyberguardx-rag-retrieval"
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / f"rag_retrieval_{report['date']}.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"RAG retrieval report: {output}")
    print(f"Questions: {count}")
    print(f"Model name: {report['model_name']}")
    print(f"FAISS backend: {report['faiss_backend']}")
    print(f"Knowledge-file hash: {report['knowledge_file_hash']}")
    print(f"Hit@1: {report['hit_at_1']:.4f}")
    print(f"Hit@3: {report['hit_at_3']:.4f}")
    print(f"Missed at top three: {len(missed)}")
    for row in missed:
        print(f"Missed question: {row['question']} | expected={row['expected_source_file']} | top source={row['top_retrieved_source']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
