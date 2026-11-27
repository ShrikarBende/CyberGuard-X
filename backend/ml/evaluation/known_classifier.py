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
    precision_recall_curve,
    auc,
    cohen_kappa_score,
    balanced_accuracy_score,
)
from sklearn.utils.class_weight import compute_class_weight
from ml.evaluation.provenance import working_tree_is_dirty
from ml.evaluation.output_paths import get_results_dir

RESULTS_DIR = get_results_dir()
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
    class_weight: Dict[str, float] | None = None,
) -> lgb.LGBMClassifier:
    print("\n[LightGBM] Training ...")
    labels = np.unique(y_train)
    base_weights = compute_class_weight(class_weight="balanced", classes=labels, y=y_train)
    weights = {int(label): float(weight) for label, weight in zip(labels, base_weights)}
    # LightGBM labels are LabelEncoder indices, aligned with class_names.
    multipliers = {"Bot": 2.5, "WebAttack": 1.5}
    multipliers.update(class_weight or {})
    for index, name in enumerate(class_names):
        if index in weights:
            multiplier = float(multipliers.get(name, multipliers.get(index, 1.0)))
            if not np.isfinite(multiplier) or multiplier <= 0:
                raise ValueError(f"Class weight multiplier for {name} must be finite and positive")
            weights[index] *= multiplier
    model = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight=None,
        random_state=seed,
        n_jobs=-1,
        verbosity=-1,
    )
    model.fit(
        X_train, y_train,
        sample_weight=np.asarray([weights[int(label)] for label in y_train], dtype=np.float64),
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

def calibrate_class_thresholds(y_val: np.ndarray, probabilities: np.ndarray,
                              class_names: List[str], classes=None,
                              target_precision: float = 0.90) -> dict:
    """Select per-class validation thresholds, preferring the requested precision target."""
    y_val = np.asarray(y_val)
    probabilities = np.asarray(probabilities, dtype=np.float64)
    classes = list(range(probabilities.shape[1])) if classes is None else list(classes)
    if probabilities.ndim != 2 or probabilities.shape[1] != len(classes) or len(y_val) != len(probabilities):
        raise ValueError("Validation labels/probabilities/classes do not align")
    if not 0 < target_precision <= 1:
        raise ValueError("target_precision must be in (0, 1]")
    output = {}
    for column, label in enumerate(classes):
        name_index = int(label) if isinstance(label, (int, np.integer)) and 0 <= int(label) < len(class_names) else column
        name = class_names[name_index] if name_index < len(class_names) else str(label)
        binary = (y_val == label).astype(int)
        scores = probabilities[:, column]
        if not binary.any():
            output[name] = {"threshold": 1.0, "validation_precision": 0.0,
                            "target_precision": float(target_precision), "target_met": False,
                            "strategy": "no positive validation samples; neutral threshold fallback"}
            continue
        precision, recall, thresholds = precision_recall_curve(binary, scores)
        eligible = np.flatnonzero(precision[:-1] >= target_precision)
        if len(eligible):
            best_recall = np.max(recall[eligible])
            tied = eligible[recall[eligible] == best_recall]
            selected = int(tied[np.argmax(thresholds[tied])])
            threshold = float(thresholds[selected])
            achieved = float(precision[selected])
            target_met = True
            strategy = "maximum validation recall subject to target precision"
        elif len(thresholds):
            f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
            selected = int(np.argmax(f1))
            threshold = float(thresholds[selected])
            achieved = float(precision[selected])
            target_met = False
            strategy = "best validation F1 fallback; target precision unavailable"
        else:
            threshold = 1.0
            achieved = 0.0
            target_met = False
            strategy = "no validation threshold available"
        output[name] = {"threshold": threshold, "validation_precision": achieved,
                        "target_precision": float(target_precision), "target_met": target_met,
                        "strategy": strategy}
    for name in class_names:
        output.setdefault(name, {"threshold": 1.0, "validation_precision": 0.0,
                                 "target_precision": float(target_precision), "target_met": False,
                                 "strategy": "class absent from fitted model; neutral threshold fallback"})
    return output

def evaluate_classifier(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: List[str],
    model_name: str,
    X_val: np.ndarray | None = None,
    y_val: np.ndarray | None = None,
    target_precision: float = 0.90,
) -> Dict:
    probabilities = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None
    calibrated_thresholds = None
    if probabilities is not None and X_val is not None and y_val is not None:
        val_probabilities = model.predict_proba(X_val)
        calibrated_thresholds = calibrate_class_thresholds(
            y_val, val_probabilities, class_names,
            classes=list(getattr(model, "classes_", range(len(class_names)))),
            target_precision=target_precision,
        )
        raw_classes = list(getattr(model, "classes_", range(len(class_names))))
        class_thresholds = np.asarray([
            calibrated_thresholds[class_names[int(label)]]["threshold"]
            if isinstance(label, (int, np.integer)) and 0 <= int(label) < len(class_names)
            else calibrated_thresholds[class_names[column]]["threshold"]
            for column, label in enumerate(raw_classes)
        ])
        qualified = probabilities >= class_thresholds[None, :]
        confidence = np.where(qualified, probabilities, -1.0)
        pred_indexes = np.argmax(confidence, axis=1)
        none_qualified = ~qualified.any(axis=1)
        if none_qualified.any():
            pred_indexes[none_qualified] = np.argmax(probabilities[none_qualified], axis=1)
        y_pred = np.asarray(raw_classes)[pred_indexes]
    else:
        y_pred = model.predict(X_test)

    report_dict = classification_report(
        y_test, y_pred,
        labels=list(range(len(class_names))),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(class_names)))).tolist()
    class_labels = list(getattr(model, "classes_", range(len(class_names))))
    per_class = {}
    for index, cls in enumerate(class_names):
        metrics = {
            "precision": round(report_dict[cls]["precision"], 6),
            "recall": round(report_dict[cls]["recall"], 6),
            "f1": round(report_dict[cls]["f1-score"], 6),
            "support": int(report_dict[cls]["support"]),
        }
        label = index
        if probabilities is not None and label in class_labels:
            col = class_labels.index(label)
            binary = (np.asarray(y_test) == label).astype(int)
            if binary.any() and (~binary.astype(bool)).any():
                precision, recall, _ = precision_recall_curve(binary, probabilities[:, col])
                metrics["auprc"] = round(float(auc(recall, precision)), 6)
            else:
                metrics["auprc"] = None
        else:
            metrics["auprc"] = None
        per_class[cls] = metrics
    valid_auprc = [row["auprc"] for row in per_class.values() if row["auprc"] is not None]

    print(f"\n{'='*60}")
    print(f"[{model_name}] Test Results")
    print(f"{'='*60}")
    print(f"  Macro-F1 (headline): {macro_f1:.4f}")
    print(f"  Accuracy           : {acc:.4f}")
    print(classification_report(y_test, y_pred, labels=list(range(len(class_names))),
                                target_names=class_names, zero_division=0))

    return {
        "model": model_name,
        "macro_f1": round(macro_f1, 6),
        "accuracy": round(acc, 6),
        "per_class": per_class,
        "macro_auprc": round(float(np.mean(valid_auprc)), 6) if valid_auprc else None,
        "imbalance_aware_summary": {
            "cohen_kappa": round(float(cohen_kappa_score(y_test, y_pred)), 6),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_test, y_pred)), 6),
        },
        "confusion_matrix": cm,
        "class_names": class_names,
        "validation_class_thresholds": calibrated_thresholds,
    }


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_known_classifier(pipeline: dict, include_xgboost: bool = True,
                         class_weight: Dict[str, float] | None = None) -> Tuple[dict, lgb.LGBMClassifier, xgb.XGBClassifier | None]:
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
    lgbm_model = train_lightgbm(X_train, y_train, X_val, y_val, class_names, seed, class_weight)
    lgbm_results = evaluate_classifier(lgbm_model, X_test, y_test, class_names, "LightGBM",
                                       X_val=X_val, y_val=y_val)

    xgb_model = None
    xgb_results = None
    if include_xgboost:
        xgb_model = train_xgboost(X_train, y_train, X_val, y_val, n_classes, seed)
        xgb_results = evaluate_classifier(xgb_model, X_test, y_test, class_names, "XGBoost",
                                          X_val=X_val, y_val=y_val)
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
        "git_dirty": pipeline.get("git_dirty", working_tree_is_dirty()),
        "flags": pipeline.get("flags", {}),
        "profile_warning": pipeline.get("reduced_profile_warning"),
        "training_time_seconds": elapsed,
        "class_weight_policy": {"base": "balanced sample weights", "class_multipliers": {"Bot": 2.5, "WebAttack": 1.5, **(class_weight or {})}},
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

