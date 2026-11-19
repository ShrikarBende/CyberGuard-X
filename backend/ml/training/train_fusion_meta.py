"""Train a calibrated logistic stacking model over the six branch outputs.

If backend/datasets/fusion_training.csv is present it must contain the six
FEATURE_NAMES plus incident_label (0/1). Otherwise a deterministic synthetic
weak-label set is used for local/CI bootstrap; its provenance is saved in bundle.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
from ml.fusion_meta import ARTIFACT_PATH, FEATURE_NAMES

DATA_PATH = BACKEND_DIR / "datasets" / "fusion_training.csv"
SEED = 2026


def generate_weak_label_data(n_samples: int = 6000, seed: int = SEED) -> tuple[np.ndarray, np.ndarray]:
    """Generate branch-score profiles with explicit, reproducible weak supervision."""
    rng = np.random.default_rng(seed)
    groups = rng.choice(4, size=n_samples, p=[0.58, 0.20, 0.15, 0.07])
    scores = np.zeros((n_samples, len(FEATURE_NAMES)), dtype=np.float64)
    for i, group in enumerate(groups):
        scores[i, :4] = rng.beta(1.4, 8.0, 4)
        if group == 1:  # endpoint-centered process/host anomaly
            scores[i, 1] = rng.beta(5.0, 1.8)
        elif group == 2:  # network and lateral-movement evidence
            scores[i, 2:4] = rng.beta(4.5, 2.0, 2)
        elif group == 3:  # account takeover plus unknown/novel flow
            scores[i, 0] = rng.beta(5.0, 1.8)
            scores[i, 2] = rng.beta(4.0, 2.0)
            scores[i, 4] = rng.beta(5.0, 1.8)
        scores[i, 4] = max(scores[i, 4], rng.beta(1.2, 8.0))
    stages = np.clip(rng.poisson(1.2 + groups * 0.8, n_samples), 0, 6)
    scores[:, 5] = stages / 6.0
    linear = (-3.0 + 2.0 * scores[:, 0] + 2.2 * scores[:, 1]
              + 2.7 * scores[:, 2] + 2.1 * scores[:, 3]
              + 2.0 * scores[:, 4] + 2.6 * scores[:, 5]
              + 1.8 * np.maximum(scores[:, 2] + scores[:, 3] - 0.8, 0))
    probability = 1.0 / (1.0 + np.exp(-linear))
    labels = rng.binomial(1, probability)
    return scores, labels.astype(np.int64)


def load_training_data(path: Path = DATA_PATH) -> tuple[np.ndarray, np.ndarray, str]:
    if path.is_file():
        frame = pd.read_csv(path)
        required = set(FEATURE_NAMES) | {"incident_label"}
        missing = required.difference(frame.columns)
        if missing:
            raise ValueError(f"Fusion training CSV missing columns: {sorted(missing)}")
        x = frame[list(FEATURE_NAMES)].to_numpy(dtype=np.float64)
        y = frame["incident_label"].astype(int).to_numpy()
        if not np.isfinite(x).all() or not np.isin(y, [0, 1]).all():
            raise ValueError("Fusion training data must be finite and incident_label must be binary")
        return x, y, str(path.resolve())
    x, y = generate_weak_label_data()
    return x, y, "synthetic_weak_labels_v1"


def _positive_coefficients(calibrator: CalibratedClassifierCV) -> np.ndarray:
    fitted = getattr(calibrator, "calibrated_classifiers_", [])
    coefficients = []
    for calibrated in fitted:
        estimator = getattr(calibrated, "estimator", getattr(calibrated, "base_estimator", None))
        if estimator is not None and hasattr(estimator, "coef_"):
            coefficients.append(np.asarray(estimator.coef_[0], dtype=np.float64))
    if not coefficients:
        raise RuntimeError("Unable to retrieve fitted logistic coefficients from calibration folds")
    return np.mean(coefficients, axis=0)


def train_fusion_meta(data_path: Path = DATA_PATH, output_path: Path = ARTIFACT_PATH,
                      feedback_samples: list[dict] | None = None) -> Path:
    x, y, source = load_training_data(data_path)
    if len(np.unique(y)) != 2 or np.bincount(y, minlength=2).min() < 5:
        raise ValueError("Fusion meta training requires at least five examples from each label")
    x_train, x_val, y_train, y_val = train_test_split(
        x, y, test_size=0.2, random_state=SEED, stratify=y
    )
    feedback_count = 0
    for sample in feedback_samples or []:
        feature_values = sample.get("fusion_features")
        target = sample.get("target")
        if not isinstance(feature_values, dict) or target not in (0, 1):
            continue
        vector = [float(feature_values.get(name, 0.0) or 0.0) for name in FEATURE_NAMES]
        if np.isfinite(vector).all():
            x_train = np.vstack([x_train, np.asarray(vector, dtype=np.float64)])
            y_train = np.append(y_train, int(target))
            feedback_count += 1
    scaler = StandardScaler().fit(x_train)
    train_scaled = scaler.transform(x_train)
    val_scaled = scaler.transform(x_val)
    model = CalibratedClassifierCV(
        estimator=LogisticRegression(class_weight="balanced", max_iter=1000, random_state=SEED),
        method="sigmoid", cv=5,
    )
    model.fit(train_scaled, y_train)
    probabilities = model.predict_proba(val_scaled)[:, 1]
    metrics = {
        "validation_brier_score": float(brier_score_loss(y_val, probabilities)),
        "validation_roc_auc": float(roc_auc_score(y_val, probabilities)),
        "validation_positive_rate": float(y_val.mean()),
        "validation_predicted_positive_rate": float((probabilities >= 0.5).mean()),
    }
    negative_validation_probabilities = probabilities[y_val == 0]
    decision_threshold = float(np.quantile(negative_validation_probabilities, 0.97)) if len(negative_validation_probabilities) else 0.5
    bundle = {
        "scaler": scaler,
        "model": model,
        "positive_coefficients": _positive_coefficients(model),
        "feature_names": list(FEATURE_NAMES),
        "model_version": "risk-fusion-logistic-calibrated-v1",
        "calibrated": True,
        "calibration_method": "sigmoid_cv5",
        "class_weight": "balanced",
        "seed": SEED,
        "training_source": source,
        "label_provenance": ("synthetic_proxy_weak_labels" if source == "synthetic_weak_labels_v1"
                             else "provided_incident_label; ground_truth_status_unspecified"),
        "feedback_samples_used": feedback_count,
        "training_rows": int(len(x_train)),
        "validation_rows": int(len(x_val)),
        "class_balance": {"train_positive_fraction": float(y_train.mean()),
                           "validation_positive_fraction": float(y_val.mean())},
        "validation_metrics": metrics,
        "validation_metrics_label_provenance": ("synthetic_proxy_weak_labels" if source == "synthetic_weak_labels_v1"
                                                else "provided_incident_label; ground_truth_status_unspecified"),
        "decision_threshold": decision_threshold,
        "threshold_calibration": "97th percentile of negative validation probabilities",
        "training_date": datetime.now(timezone.utc).isoformat(),
        "severity_thresholds": {"LOW": [0.0, 0.25], "MEDIUM": [0.25, 0.5],
                                "HIGH": [0.5, 0.75], "CRITICAL": [0.75, 1.0]},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path, compress=3)
    print(json.dumps({"artifact": str(output_path.resolve()), "metrics": metrics,
                      "class_balance": bundle["class_balance"], "training_source": source}, indent=2))
    return output_path


if __name__ == "__main__":
    train_fusion_meta()
