"""Test-only synthetic smoke fixture for leave-one-family-out evaluation."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.evaluation import open_set_pipeline


@pytest.fixture
def test_only_synthetic_open_set_pipeline():
    """Synthetic rows for this test only; never used as benchmark results."""
    rng = np.random.default_rng(2026)
    centers = {
        "BENIGN": (-4.0, -4.0),
        "PortScan": (0.0, 4.0),
        "DosDDoS": (4.0, -2.0),
        "HeldOutFamily": (8.0, 8.0),
    }

    def rows(counts):
        data = []
        for label, count in counts.items():
            center = np.asarray(centers[label], dtype=np.float32)
            points = center + rng.normal(0, 0.2, size=(count, 2)).astype(np.float32)
            data.extend({"f1": point[0], "f2": point[1], "Label": label} for point in points)
        return pd.DataFrame(data)

    return {
        "train_df": rows({"BENIGN": 80, "PortScan": 80, "DosDDoS": 80, "HeldOutFamily": 20}),
        "val_df": rows({"BENIGN": 18, "PortScan": 18, "DosDDoS": 18, "HeldOutFamily": 7}),
        "test_df": rows({"BENIGN": 12, "PortScan": 12, "DosDDoS": 12, "HeldOutFamily": 12}),
        "feat_cols": ["f1", "f2"],
        "seed": 42,
        "train_row_cap_per_fold": 90,
        "detectors": [
            "confidence", "isolation_forest", "mahalanobis",
            "confidence_mahalanobis_rank_average", "union_conf_mahalanobis",
        ],
        "isolation_forest": {"n_estimators": 5, "max_samples": 20, "n_jobs": 1},
        "bootstrap_resamples": 5,
        "log1p": False,
    }


def test_evaluate_one_family_caps_only_train_and_thresholds_known_validation(
    test_only_synthetic_open_set_pipeline, monkeypatch
):
    pipeline = test_only_synthetic_open_set_pipeline
    seen = {"threshold_calls": [], "folds": None}
    original_filter = open_set_pipeline.known_fold_frames
    original_threshold = open_set_pipeline.threshold_from_known_validation

    def track_folds(train_df, val_df, held_out_family, label_col="Label"):
        filtered_train, filtered_val = original_filter(train_df, val_df, held_out_family, label_col)
        seen["folds"] = (set(filtered_train[label_col]), set(filtered_val[label_col]))
        return filtered_train, filtered_val

    def track_threshold(scores, known_mask, percentile=open_set_pipeline.THRESHOLD_PERCENTILE):
        seen["threshold_calls"].append(
            (np.asarray(scores).copy(), np.asarray(known_mask).copy(), percentile)
        )
        return original_threshold(scores, known_mask, percentile)

    monkeypatch.setattr(open_set_pipeline, "known_fold_frames", track_folds)
    monkeypatch.setattr(open_set_pipeline, "threshold_from_known_validation", track_threshold)
    result = open_set_pipeline.evaluate_one_family(
        "HeldOutFamily", pipeline, progress_state=None
    )

    assert "HeldOutFamily" not in seen["folds"][0]
    assert "HeldOutFamily" not in seen["folds"][1]
    assert result["row_counts"]["train"] == 90
    assert result["row_counts"]["validation"] == 54
    assert result["row_counts"]["test_known"] == 36
    assert result["row_counts"]["test_unknown"] == 12
    assert result["train_cap_per_fold"] == 90
    assert len(seen["threshold_calls"]) == 6
    for scores, mask, _ in seen["threshold_calls"]:
        assert len(scores) == 54
        assert mask.all()
    known_validation_scores, _, _ = seen["threshold_calls"][0]
    expected_threshold = np.percentile(
        known_validation_scores, open_set_pipeline.THRESHOLD_PERCENTILE
    )
    assert result["detectors"]["confidence"]["threshold_value"] == pytest.approx(
        expected_threshold, abs=1e-6
    )
    for scores, _, percentile in seen["threshold_calls"][-2:]:
        assert percentile == pytest.approx(97.5)
    assert result["detectors"]["union_conf_mahalanobis"]["threshold_percentile"] == 97.5
    union_thresholds = result["detectors"]["union_conf_mahalanobis"]["threshold_value"]
    assert union_thresholds["confidence_score_97_5th_percentile"] == pytest.approx(
        np.percentile(seen["threshold_calls"][-2][0], 97.5)
    )
    assert union_thresholds["mahalanobis_score_97_5th_percentile"] == pytest.approx(
        np.percentile(seen["threshold_calls"][-1][0], 97.5)
    )
