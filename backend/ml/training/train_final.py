"""Train the live CICIDS2017 LightGBM bundle using an evaluation profile split."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import joblib
import lightgbm as lgb
import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.preprocessing.cicids_pipeline import (  # noqa: E402
    LABEL_COL,
    apply_log1p_columns,
    build_full_pipeline,
    fit_log1p_columns,
)
from ml.open_set import compute_centroid_statistics, nearest_centroid_distance  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.decomposition import PCA  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from ml.open_set import calibrated_union_score, temperature_scaled_energy  # noqa: E402

SEED = 42
LIGHT_SAMPLE = 0.15
MEDIUM_SAMPLE = 0.5
MODEL_VERSION = "cicids2017-light-v1"
ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "cicids2017_lightgbm.bundle.pkl"
MEDIUM_ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "cicids2017_medium_lightgbm.bundle.pkl"
EVALUATION_DIR = BACKEND_DIR / "ml" / "evaluation" / "results"


SCORE_NAME = "logit_margin"
OPEN_SET_SPECIFICITY = 0.97
ENERGY_TEMPERATURE = 1.5


def compute_margin_tau(
    raw_scores: np.ndarray,
    validation_labels: Sequence[object],
    known_class_names: Sequence[object],
) -> float:
    """Return the 5th percentile of known validation top-two logit margins.

    Any label outside the model's known class set is rejected. This prevents
    unknown rows from entering threshold selection, even if appended by mistake.
    """
    raw_scores = np.asarray(raw_scores, dtype=np.float64)
    labels = np.asarray(validation_labels)
    known = np.asarray(list(known_class_names))
    if raw_scores.ndim != 2 or raw_scores.shape[0] != labels.shape[0]:
        raise ValueError("Validation raw scores and labels must have matching rows.")
    if raw_scores.shape[0] == 0:
        raise ValueError("At least one known validation row is required to compute tau.")
    if not np.isin(labels, known).all():
        raise ValueError("Tau may only use known-class validation rows.")
    if raw_scores.shape[1] < 2 or not np.isfinite(raw_scores).all():
        raise ValueError("Validation raw scores must be finite and have at least two classes.")
    ordered = np.sort(raw_scores, axis=1)
    margins = ordered[:, -1] - ordered[:, -2]
    return float(np.quantile(margins, 0.05))


def find_corresponding_evaluation(profile: str, seed: int, split_type: str, sample_fraction: float) -> str | None:
    """Find an evaluation artifact matching the training configuration."""
    matches = []
    for path in EVALUATION_DIR.glob("known_classifier_*.json"):
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (
            metadata.get("seed") == seed
            and metadata.get("split_type") == split_type
            and metadata.get("profile_name", metadata.get("profile")) == profile
            and float(metadata.get("sample_fraction", 1.0)) == sample_fraction
        ):
            matches.append(path)
    if not matches:
        return None
    return str(max(matches, key=lambda p: p.stat().st_mtime).resolve())


def train_final(
    force_reload: bool = False,
    profile: str = "light",
    output_path: Path | None = None,
    feedback_samples: list[dict] | None = None,
) -> Path:
    """Fit on train only, calibrate tau on known validation only, and save bundle."""
    if profile not in {"light", "medium"}:
        raise ValueError("profile must be 'light' or 'medium'")
    sample = LIGHT_SAMPLE if profile == "light" else MEDIUM_SAMPLE
    artifact_path = Path(output_path) if output_path is not None else (
        ARTIFACT_PATH if profile == "light" else MEDIUM_ARTIFACT_PATH
    )
    model_version = "cicids2017-light-v1" if profile == "light" else "cicids2017-medium-v1"
    pipeline = build_full_pipeline(
        force_reload=force_reload,
        seed=SEED,
        sample=sample,
        log1p=True,
    )
    class_names = list(pipeline["class_names"])
    if "BENIGN" not in class_names:
        raise ValueError("The CICIDS2017 known classes must include BENIGN.")

    model = lgb.LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=63,
        max_depth=-1,
        min_child_samples=20,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1,
        verbosity=-1,
    )
    # Analyst-verified feedback is appended only to training rows; validation
    # remains untouched and continues to calibrate every open-set threshold.
    raw_train = pipeline["train_df"][pipeline["feat_cols"]].to_numpy(dtype=np.float32)
    log1p_columns = fit_log1p_columns(raw_train)
    feedback_x, feedback_y = [], []
    class_to_index = {name: index for index, name in enumerate(class_names)}
    for sample_row in feedback_samples or []:
        raw_features = sample_row.get("flow_features")
        label = sample_row.get("predicted_class") if int(sample_row.get("target", 0)) == 1 else "BENIGN"
        if not isinstance(raw_features, dict) or label not in class_to_index:
            continue
        try:
            raw_row = np.asarray([[float(raw_features[name]) for name in pipeline["feat_cols"]]], dtype=np.float32)
        except (KeyError, TypeError, ValueError):
            continue
        if not np.isfinite(raw_row).all():
            continue
        transformed = apply_log1p_columns(raw_row, np.asarray(log1p_columns, dtype=bool))
        feedback_x.append(pipeline["scaler"].transform(transformed)[0])
        feedback_y.append(class_to_index[label])
    X_fit = np.asarray(pipeline["X_train"], dtype=np.float32)
    y_fit = np.asarray(pipeline["y_train"])
    if feedback_x:
        X_fit = np.vstack([X_fit, np.asarray(feedback_x, dtype=np.float32)])
        y_fit = np.concatenate([y_fit, np.asarray(feedback_y, dtype=y_fit.dtype)])
    model.fit(X_fit, y_fit)

    val_raw_scores = model.predict(pipeline["X_val"], raw_score=True)
    validation_labels = pipeline["le"].inverse_transform(pipeline["y_val"])
    tau = compute_margin_tau(val_raw_scores, validation_labels, class_names)

    # Centroids/covariance and IF are fit on training rows only. Their rejection
    # thresholds and score ranges are calibrated on known validation rows only.
    X_train = np.asarray(X_fit, dtype=np.float64)
    X_val = np.asarray(pipeline["X_val"], dtype=np.float64)
    y_train = np.asarray(y_fit)
    compact_scaler = StandardScaler().fit(X_train)
    compact_pca = PCA(n_components=min(16, X_train.shape[1]), random_state=SEED).fit(compact_scaler.transform(X_train))
    compact_train = compact_pca.transform(compact_scaler.transform(X_train))
    compact_val = compact_pca.transform(compact_scaler.transform(X_val))
    centroid_classes, centroids, covariance = compute_centroid_statistics(compact_train, y_train)
    val_distance = nearest_centroid_distance(compact_val, centroids, covariance)
    validation_probabilities = model.predict_proba(X_val)
    val_logits = np.asarray(model.predict(X_val, raw_score=True), dtype=np.float64)
    val_confidence_anomaly = 1.0 - validation_probabilities.max(axis=1)
    val_energy_anomaly = temperature_scaled_energy(val_logits, ENERGY_TEMPERATURE)
    sorted_val_logits = np.sort(val_logits, axis=1)
    val_margin_anomaly = -(sorted_val_logits[:, -1] - sorted_val_logits[:, -2])
    confidence_anomaly_threshold = float(np.quantile(val_confidence_anomaly, OPEN_SET_SPECIFICITY))
    energy_anomaly_threshold = float(np.quantile(val_energy_anomaly, OPEN_SET_SPECIFICITY))
    compact_distance_threshold = float(np.quantile(val_distance, OPEN_SET_SPECIFICITY))
    benign_index = class_names.index("BENIGN")
    benign_train = X_train[y_train == benign_index]
    iforest = IsolationForest(n_estimators=200, contamination="auto", random_state=SEED, n_jobs=-1)
    iforest.fit(benign_train)
    val_anomaly = -iforest.score_samples(X_val)
    component_references = {
        "confidence": val_confidence_anomaly,
        "energy": val_energy_anomaly,
        "logit_margin": val_margin_anomaly,
        "compact_mahalanobis": val_distance,
        "isolation_forest": val_anomaly,
    }
    val_union_score = calibrated_union_score(component_references, component_references)
    union_threshold = float(np.quantile(val_union_score, OPEN_SET_SPECIFICITY))
    anomaly_bounds = (float(np.quantile(val_anomaly, 0.05)), float(np.quantile(val_anomaly, OPEN_SET_SPECIFICITY)))

    split_type = pipeline.get("split_type", "stratified_random")
    evaluation_json_path = find_corresponding_evaluation("light", SEED, split_type, LIGHT_SAMPLE)
    bundle = {
        "model": model,
        "scaler": pipeline["scaler"],
        "feature_names": list(pipeline["feat_cols"]),
        "log1p_columns": log1p_columns,
        "class_names": class_names,
        "tau": tau,
        "centroid_classes": centroid_classes,
        "class_centroids": centroids,
        "centroid_covariance": covariance,
        "compact_scaler": compact_scaler,
        "compact_pca": compact_pca,
        "compact_feature_count": int(compact_pca.n_components_),
        "centroid_distance_threshold": compact_distance_threshold,
        "centroid_distance_bounds": (float(np.quantile(val_distance, 0.05)), compact_distance_threshold),
        "confidence_threshold": float(1.0 - confidence_anomaly_threshold),
        "confidence_anomaly_threshold": confidence_anomaly_threshold,
        "energy_temperature": ENERGY_TEMPERATURE,
        "energy_anomaly_threshold": energy_anomaly_threshold,
        "margin_anomaly_threshold": float(np.quantile(val_margin_anomaly, OPEN_SET_SPECIFICITY)),
        "open_set_component_references": {name: np.sort(values) for name, values in component_references.items()},
        "open_set_union_threshold": union_threshold,
        "open_set_validation_specificity_target": OPEN_SET_SPECIFICITY,
        "open_set_isolation_forest": iforest,
        "anomaly_score_bounds": anomaly_bounds,
        "anomaly_score_threshold": anomaly_bounds[1],
        "score_name": SCORE_NAME,
        "model_version": model_version,
        "data_hash": pipeline["data_hash"],
        "seed": SEED,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "evaluation_json_path": evaluation_json_path,
        "evaluation_config": {
            "profile": profile,
            "seed": SEED,
            "split_type": split_type,
            "sample_fraction": sample,
        },
        "profile": {"name": profile, "sample_fraction": sample, "log1p": True},
        "split_type": split_type,
        "training_parameters": {"n_estimators": 400, "early_stopping": False},
        "feedback_adaptation": {"samples_used": len(feedback_x),
                                "open_set_threshold_calibration": "known validation only"},
    }
    if profile == "medium":
        matching = EVALUATION_DIR / "open_set_cicids_medium_seed42.json"
        if matching.is_file():
            bundle["evaluation_json_path"] = str(matching.resolve())
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, artifact_path, compress=3)
    size_bytes = artifact_path.stat().st_size
    print(f"Artifact: {artifact_path}")
    print(f"Artifact size: {size_bytes} bytes ({size_bytes / (1024 * 1024):.2f} MiB)")
    print(f"Model version: {model_version}; profile: {profile}; tau: {tau:.8f}; data_hash: {pipeline['data_hash']}")
    if bundle["evaluation_json_path"]:
        print(f"Evaluation JSON: {bundle['evaluation_json_path']}")
    else:
        print("Evaluation JSON: no file matches profile, seed, split_type, and sample_fraction; no evaluation was run.")
    return artifact_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force-reload", action="store_true")
    parser.add_argument("--profile", choices=["light", "medium"], default="medium")
    args = parser.parse_args()
    train_final(force_reload=args.force_reload, profile=args.profile)
