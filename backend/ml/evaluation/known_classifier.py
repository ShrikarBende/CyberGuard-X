"""
Known-Class Multi-Class Classifier
====================================
Trains LightGBM (primary) and XGBoost (comparison) on all known CICIDS2017 classes.
Reports per-class precision / recall / F1, macro-F1, and confusion matrix on test.
Accuracy is shown but NOT the headline metric (class imbalance).

All metrics are computed from actual test-set predictions — never hardcoded.
Results saved to backend/ml/evaluation/results/known_classifier_<date>.json
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import lightgbm as lgb
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42


# ─── LightGBM ────────────────────────────────────────────────────────────────

def train_lightgbm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    class_names: List[str],
    seed: int = SEED,
) -> lgb.LGBMClassifier:
    print("\n[LightGBM] Training ...")
    model = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
        verbosity=-1,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(-1)],
    )
    print(f"  Best iteration: {model.best_iteration_}")
    return model


# ─── XGBoost ─────────────────────────────────────────────────────────────────

def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    n_classes: int,
    seed: int = SEED,
) -> xgb.XGBClassifier:
    print("\n[XGBoost] Training ...")
    model = xgb.XGBClassifier(
        n_estimators=400,
        learning_rate=0.05,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        num_class=n_classes,
        objective="multi:softprob",
        eval_metric="mlogloss",
        use_label_encoder=False,
        early_stopping_rounds=50,
        random_state=seed,
        n_jobs=-1,
        verbosity=0,
    )
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )
    print(f"  Best iteration: {model.best_iteration}")
    return model


# ─── Evaluation helper ────────────────────────────────────────────────────────

def evaluate_classifier(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: List[str],
    model_name: str,
) -> Dict:
    y_pred = model.predict(X_test)

    report_dict = classification_report(
        y_test, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n{'='*60}")
    print(f"[{model_name}] Test Results")
    print(f"{'='*60}")
    print(f"  Macro-F1 (headline): {macro_f1:.4f}")
    print(f"  Accuracy           : {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    return {
        "model": model_name,
        "macro_f1": round(macro_f1, 6),
        "accuracy": round(acc, 6),
        "per_class": {
            cls: {
                "precision": round(report_dict[cls]["precision"], 6),
                "recall":    round(report_dict[cls]["recall"],    6),
                "f1":        round(report_dict[cls]["f1-score"],  6),
                "support":   int(report_dict[cls]["support"]),
            }
            for cls in class_names
        },
        "confusion_matrix": cm,
        "class_names": class_names,
    }


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_known_classifier(pipeline: dict, include_xgboost: bool = True) -> Tuple[dict, lgb.LGBMClassifier, xgb.XGBClassifier | None]:
    """
    Train + evaluate known-class models. XGBoost can be omitted by lightweight profiles.
    Returns (results_dict, lgbm_model, optional_xgb_model).
    """
    X_train = pipeline["X_train"]
    y_train = pipeline["y_train"]
    X_val   = pipeline["X_val"]
    y_val   = pipeline["y_val"]
    X_test  = pipeline["X_test"]
    y_test  = pipeline["y_test"]
    class_names = pipeline["class_names"]
    n_classes   = len(class_names)
    seed        = pipeline["seed"]

    t0 = time.time()
    lgbm_model = train_lightgbm(X_train, y_train, X_val, y_val, class_names, seed)
    lgbm_results = evaluate_classifier(lgbm_model, X_test, y_test, class_names, "LightGBM")

    xgb_model = None
    xgb_results = None
    if include_xgboost:
        xgb_model = train_xgboost(X_train, y_train, X_val, y_val, n_classes, seed)
        xgb_results = evaluate_classifier(xgb_model, X_test, y_test, class_names, "XGBoost")
    elapsed = round(time.time() - t0, 2)

    results = {
        "pipeline_stage": "known_classifier",
        "model_version": "v2.0",
        "data_hash": pipeline["data_hash"],
        "seed": seed,
        "date": datetime.utcnow().isoformat(),
        "row_counts": pipeline.get("row_counts", {}),
        "split_type": pipeline.get("split_type", "stratified_random"),
        "split_warning": pipeline.get("split_warning", "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic."),
        "profile_name": pipeline.get("profile_name", "full"),
        "sample_fraction": pipeline.get("sample_fraction", 1.0),
        "train_row_cap_per_fold": pipeline.get("train_row_cap_per_fold"),
        "bootstrap_resamples": pipeline.get("bootstrap_resamples", 1000),
        "git_hash": pipeline.get("git_hash"),
        "flags": pipeline.get("flags", {}),
        "profile_warning": pipeline.get("reduced_profile_warning"),
        "training_time_seconds": elapsed,
        "excluded_labels": ["Heartbleed", "Infiltration"],
        "note": "Macro-F1 is the headline metric; accuracy not used due to class imbalance.",
        "LightGBM": lgbm_results,
    }
    if include_xgboost:
        results["XGBoost"] = xgb_results

    out_path = RESULTS_DIR / f"known_classifier_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.json"
    results["results_path"] = str(out_path)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[known_classifier] Results saved -> {out_path}")

    return results, lgbm_model, xgb_model


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ml.preprocessing.cicids_pipeline import build_full_pipeline

    pipeline = build_full_pipeline()
    run_known_classifier(pipeline)

