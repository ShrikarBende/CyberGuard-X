from __future__ import annotations

import numpy as np

from app.ingestion.scenarios import generate_all_taxonomy_scenarios, TAXONOMY_SCENARIOS_METADATA
from app.correlation.indicators import evaluate_indicators
from ml.evaluation.known_classifier import evaluate_classifier, calibrate_class_thresholds
from ml.evaluation import evaluate_rag_quality as rag_eval


def test_taxonomy_generates_all_core_scenarios_and_baselines():
    events = generate_all_taxonomy_scenarios()
    names = {row["scenario"] for row in events}
    assert set(TAXONOMY_SCENARIOS_METADATA).issubset(names)
    assert {"benign_admin", "normal_employee_day"}.issubset(names)
    rules = {item["name"] for item in evaluate_indicators(events)}
    assert {"impossible_travel", "credential_stuffing_burst", "ransomware_burst",
            "lolbin_execution", "dns_tunneling"}.issubset(rules)


def test_classifier_includes_imbalance_metrics_and_auprc():
    class Model:
        classes_ = np.array([0, 1])
        def predict(self, _X): return np.array([0, 1, 1, 0])
        def predict_proba(self, _X): return np.array([[.9,.1],[.2,.8],[.3,.7],[.8,.2]])
    report = evaluate_classifier(Model(), np.zeros((4, 1)), np.array([0, 1, 1, 0]),
                                 ["benign", "attack"], "test")
    assert report["per_class"]["attack"]["auprc"] is not None
    assert report["macro_auprc"] is not None
    assert "cohen_kappa" in report["imbalance_aware_summary"]
    assert "balanced_accuracy" in report["imbalance_aware_summary"]


def test_validation_threshold_calibration_handles_missing_class():
    thresholds = calibrate_class_thresholds(
        np.array([0, 0]), np.array([[.9, .1], [.8, .2]]), ["BENIGN", "Bot"]
    )
    assert thresholds["Bot"]["threshold"] == 1.0
    assert not thresholds["Bot"]["target_met"]


def test_rag_quality_evaluator_computes_retrieval_and_groundedness(monkeypatch, tmp_path):
    class Retriever:
        def search(self, _query, top_k=3):
            return [{"source_file": "expected.md"}]
    monkeypatch.setattr(rag_eval, "get_results_dir", lambda: tmp_path)
    result = rag_eval.evaluate_rag_quality(
        retriever=Retriever(), questions=[{"question": "q", "expected_source_file": "expected.md"}],
        reports=[{"asserted_facts": ["event-1"], "retrieved_context": "event-1",
                  "citations": ["chunk-1"], "allowed_chunk_ids": ["chunk-1"]}],
        mapping_cases=[{"predicted": ["T1110"], "expected": ["T1110"]}],
    )
    assert result["retrieval"]["hit_at_1"] == 1
    assert result["retrieval"]["mrr"] == 1
    assert result["groundedness"]["score"] == 1
    assert result["mitre_mapping"]["f1_score"] == 1
    assert (tmp_path / "rag_quality_evaluation.json").is_file()
