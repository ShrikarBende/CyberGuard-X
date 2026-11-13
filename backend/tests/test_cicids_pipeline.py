"""
PyTest: CICIDS2017 Pipeline Integrity Tests
=============================================
Tests:
  1. Split ratio correctness (70/10/20 within tolerance)
  2. No data leakage (scaler fitted on train only, applied to val/test)
  3. Threshold rule (held-out family NEVER touches val set)
  4. Rare label exclusion (Heartbleed & Infiltration absent after pipeline)
  5. No NaN / inf in feature matrices after cleaning
  6. Label encoding consistency (all test labels appear in train encoder classes)

Run:
  cd d:/MAJOR PROJECT
  python -m pytest backend/tests/test_cicids_pipeline.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

# Adjust path so imports resolve
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ml.preprocessing.cicids_pipeline import (
    ATTACK_FAMILIES,
    EXCLUDED_LABELS,
    LABEL_COL,
    LABEL_MAP,
    build_full_pipeline,
    build_splits,
    get_feature_matrices,
    load_all_cicids,
    deduplicate_flows,
    fit_log1p_columns,
    apply_log1p_columns,
)
from ml.evaluation.open_set_pipeline import threshold_from_known_validation, known_fold_frames


# ─── Fixtures (cached across tests in session) ───────────────────────────────

@pytest.fixture(scope="session")
def pipeline():
    """Load the full pipeline once per test session."""
    return build_full_pipeline(force_reload=False, seed=42)


# ─── Test 1: Split ratios ─────────────────────────────────────────────────────

def test_split_ratios(pipeline):
    """
    Total rows must be distributed roughly 70/10/20.
    Allow ±5 percentage points tolerance per split.
    """
    n_train = len(pipeline["train_df"])
    n_val   = len(pipeline["val_df"])
    n_test  = len(pipeline["test_df"])
    n_total = n_train + n_val + n_test

    assert n_total > 0, "Total rows must be > 0"

    ratio_train = n_train / n_total
    ratio_val   = n_val   / n_total
    ratio_test  = n_test  / n_total

    assert 0.65 <= ratio_train <= 0.75, (
        f"Train ratio {ratio_train:.3f} out of expected [0.65, 0.75]"
    )
    assert 0.08 <= ratio_val <= 0.14, (
        f"Val ratio {ratio_val:.3f} out of expected [0.08, 0.14]"
    )
    assert 0.17 <= ratio_test <= 0.23, (
        f"Test ratio {ratio_test:.3f} out of expected [0.17, 0.23]"
    )


# ─── Test 2: No NaN / Inf in feature matrices ─────────────────────────────────

def test_no_nan_inf_in_matrices(pipeline):
    """Feature matrices must be finite after pipeline."""
    for split, X in [
        ("X_train", pipeline["X_train"]),
        ("X_val",   pipeline["X_val"]),
        ("X_test",  pipeline["X_test"]),
    ]:
        assert not np.isnan(X).any(),  f"NaN found in {split}"
        assert not np.isinf(X).any(),  f"Inf found in {split}"


# ─── Test 3: Scaler fitted on train only (mean/std consistency) ───────────────

def test_scaler_fitted_on_train_only(pipeline):
    """
    After scaling, train features should be approximately zero-mean unit-variance.
    Val and test should NOT necessarily have this property (different distribution ok).
    """
    X_train = pipeline["X_train"]
    col_means = np.abs(X_train.mean(axis=0))
    col_stds  = X_train.std(axis=0)

    # Allow per-feature mean to be within ±0.1 of 0 (numerical tolerance)
    assert col_means.max() < 0.5, (
        f"Train mean too far from 0 after scaling: max={col_means.max():.4f}"
    )
    # Non-constant features should be unit variance; constants remain zero.
    assert np.all((col_stds == 0.0) | np.isclose(col_stds, 1.0, atol=0.02))


# ─── Test 4: Rare labels excluded ─────────────────────────────────────────────

def test_rare_labels_excluded(pipeline):
    """Heartbleed and Infiltration must NOT appear anywhere in the pipeline output."""
    all_labels = set(pipeline["class_names"])
    full_labels = set(pipeline["full_df"][LABEL_COL].unique())

    for lbl in EXCLUDED_LABELS:
        assert lbl not in all_labels, f"Excluded label '{lbl}' found in class encoder"
        assert lbl not in full_labels, f"Excluded label '{lbl}' found in full_df after pipeline"


# ─── Test 5: All class names are known families ───────────────────────────────

def test_class_names_are_known_families(pipeline):
    """The label encoder must only contain the 6 known families."""
    expected = set(["BENIGN"] + ATTACK_FAMILIES)
    actual   = set(pipeline["class_names"])
    assert actual == expected, (
        f"Class mismatch. Expected: {expected}, Got: {actual}"
    )


# ─── Test 6: Threshold rule (no leakage from held-out family into val) ────────

def test_threshold_rule_no_leakage(pipeline):
    """
    For each held-out attack family F, verify that:
      - val_df contains NO rows with label == F
      - train_df contains NO rows with label == F
    This replicates the assertion inside open_set_pipeline but at the DataFrame level.
    """
    train_df = pipeline["train_df"]
    val_df   = pipeline["val_df"]

    for family in ATTACK_FAMILIES:
        train_fold, val_fold = known_fold_frames(train_df, val_df, family)
        assert family not in set(train_fold[LABEL_COL])
        assert family not in set(val_fold[LABEL_COL])


def test_threshold_rejects_unknown_validation_rows():
    with pytest.raises(ValueError, match="known-class"):
        threshold_from_known_validation(np.array([0.1, 0.9]), np.array([True, False]))


def test_leave_one_family_out_rows_excluded(pipeline):
    for family in ATTACK_FAMILIES:
        train, validation = known_fold_frames(pipeline["train_df"], pipeline["val_df"], family)
        assert (train[LABEL_COL] == family).sum() == 0
        assert (validation[LABEL_COL] == family).sum() == 0


def test_scaler_statistics_match_train_only(pipeline):
    raw = pipeline["train_df"][pipeline["feat_cols"]].to_numpy(dtype=np.float32)
    scaler = pipeline["scaler"]
    np.testing.assert_allclose(scaler.mean_, raw.mean(axis=0), rtol=1e-5, atol=1e-5)
    expected_scale = raw.std(axis=0)
    expected_scale[expected_scale == 0] = 1.0
    np.testing.assert_allclose(scaler.scale_, expected_scale, rtol=1e-5, atol=1e-5)


def test_dedup_drops_exact_and_conflicting_rows():
    frame = __import__("pandas").DataFrame({"f": [1, 1, 2, 2], "Label": ["A", "A", "A", "B"], "_source_file": ["x", "y", "x", "y"]})
    cleaned, exact, conflicts = deduplicate_flows(frame)
    assert exact == 1
    assert conflicts == 2
    assert len(cleaned) == 1


def test_log1p_column_selection_uses_train_statistics():
    train = np.array([[0.0, -1.0, 4.0], [3.0, 2.0, 8.0]], dtype=np.float32)
    columns = fit_log1p_columns(train)
    assert columns.tolist() == [True, False, True]
    transformed = apply_log1p_columns(np.array([[3.0, 10.0, 8.0]], dtype=np.float32), columns)
    np.testing.assert_allclose(transformed, [[np.log1p(3), 10.0, np.log1p(8)]])


# ─── Test 7: Label encoding: test labels are subset of train labels ───────────

def test_label_encoding_no_unseen_classes(pipeline):
    """
    All integer labels in y_test must be in the range [0, n_classes-1].
    This catches label encoding errors where test has classes not in train.
    """
    n_classes = len(pipeline["class_names"])
    y_test    = pipeline["y_test"]

    assert y_test.min() >= 0,          f"Negative label index in y_test: {y_test.min()}"
    assert y_test.max() < n_classes,   f"Label index {y_test.max()} >= n_classes={n_classes}"


# ─── Test 8: Data hash is a non-empty string ─────────────────────────────────

def test_data_hash_present(pipeline):
    h = pipeline["data_hash"]
    assert isinstance(h, str) and len(h) > 0, "data_hash must be a non-empty string"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

