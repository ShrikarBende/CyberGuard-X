"""Tests for centroid-based unknown rejection and OSCR evaluation."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.open_set import (calibrated_union_score, compute_centroid_statistics, decide_open_set,
                         nearest_centroid_distance, temperature_scaled_energy)
from ml.evaluation.open_set_pipeline import oscr_curve
from app.detection.engine import predict_flow
from app.detection.engine import score_batch
import pandas as pd


def test_centroid_distance_is_nearest_mahalanobis_distance():
    labels = np.array([0, 0, 1, 1])
    values = np.array([[0.0, 0.0], [0.2, 0.0], [5.0, 5.0], [5.2, 5.0]])
    classes, centroids, covariance = compute_centroid_statistics(values, labels)
    distances = nearest_centroid_distance(np.array([[0.1, 0.0], [20.0, 20.0]]), centroids, covariance)
    assert classes == [0, 1]
    assert distances[0] < distances[1]


def test_out_of_distribution_inputs_are_flagged_unknown():
    probabilities = np.array([[0.99, 0.01], [0.55, 0.45]])
    flagged = decide_open_set(
        probabilities, margins=np.array([4.0, 0.1]), distances=np.array([0.2, 9.0]),
        distance_threshold=3.0, confidence_threshold=0.6, anomaly=np.array([0.1, 0.9]),
        anomaly_threshold=0.7, margin_threshold=1.0,
    )
    np.testing.assert_array_equal(flagged, [False, True])


def test_live_flow_inference_returns_unknown_novel_for_centroid_outlier():
    class IdentityScaler:
        def transform(self, values):
            return values

    class ConfidentModel:
        def predict(self, values, raw_score=False):
            return np.tile([[0.0, 10.0]], (len(values), 1))

        def predict_proba(self, values):
            return np.tile([[0.01, 0.99]], (len(values), 1))

    bundle = {
        "model": ConfidentModel(), "scaler": IdentityScaler(),
        "feature_names": ["a", "b"], "log1p_columns": [False, False],
        "class_names": ["BENIGN", "PortScan"], "tau": 0.1,
        "score_name": "logit_margin", "model_version": "centroid-test",
        "class_centroids": np.array([[0.0, 0.0], [1.0, 1.0]]),
        "centroid_covariance": np.eye(2), "centroid_distance_threshold": 2.0,
        "centroid_distance_bounds": (0.1, 2.0), "confidence_threshold": 0.5,
        "open_set_isolation_forest": None,
    }
    result = predict_flow({"a": 100.0, "b": 100.0}, bundle)
    assert result["predicted_class"] == "PortScan"
    assert result["verdict"] == "UNKNOWN_NOVEL"
    assert result["open_set_label"] == "UNKNOWN_NOVEL"
    assert result["centroid_distance"] > bundle["centroid_distance_threshold"]
    batch = score_batch(pd.DataFrame([{"a": 100.0, "b": 100.0}]), bundle)
    assert batch[0]["verdict"] == "UNKNOWN_NOVEL"


def test_oscr_auc_bounds_and_curve_is_monotonic():
    correct = np.array([True, True, False, True])
    known_scores = np.array([0.05, 0.2, 0.4, 0.8])
    unknown_scores = np.array([0.3, 0.7, 0.9])
    fpr, ccr, auc = oscr_curve(correct, unknown_scores, known_scores)
    assert 0.0 <= auc <= 1.0
    assert np.all(np.diff(fpr) >= 0)
    assert np.all(np.diff(ccr) >= 0)
    assert fpr[0] == ccr[0] == 0.0
    assert fpr[-1] == 1.0


def test_energy_and_joint_calibration_use_known_reference_scores():
    logits = np.array([[8.0, 0.0], [0.0, 0.0]])
    energy = temperature_scaled_energy(logits, temperature=1.5)
    assert energy[1] > energy[0]
    references = {"confidence": np.array([0.0, 0.1, 0.2, 0.3]),
                  "distance": np.array([0.0, 1.0, 2.0, 3.0])}
    union = calibrated_union_score(references, {"confidence": np.array([0.31]), "distance": np.array([0.5])})
    assert union[0] >= 0.75
