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

SEED = 42
LIGHT_SAMPLE = 0.15
MEDIUM_SAMPLE = 0.5
MODEL_VERSION = "cicids2017-light-v1"
ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "cicids2017_lightgbm.bundle.pkl"
MEDIUM_ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "cicids2017_medium_lightgbm.bundle.pkl"
EVALUATION_DIR = BACKEND_DIR / "ml" / "evaluation" / "results"


SCORE_NAME = "logit_margin"


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
    # Validation data is deliberately excluded from model fitting.
    model.fit(pipeline["X_train"], pipeline["y_train"])

    val_raw_scores = model.predict(pipeline["X_val"], raw_score=True)
    validation_labels = pipeline["le"].inverse_transform(pipeline["y_val"])
    tau = compute_margin_tau(val_raw_scores, validation_labels, class_names)

    raw_train = pipeline["train_df"][pipeline["feat_cols"]].to_numpy(dtype=np.float32)
    log1p_columns = fit_log1p_columns(raw_train)
    split_type = pipeline.get("split_type", "stratified_random")
    evaluation_json_path = find_corresponding_evaluation("light", SEED, split_type, LIGHT_SAMPLE)
    bundle = {
        "model": model,
        "scaler": pipeline["scaler"],
        "feature_names": list(pipeline["feat_cols"]),
        "log1p_columns": log1p_columns,
        "class_names": class_names,
        "tau": tau,
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
    parser.add_argument("--profile", choices=["light", "medium"], default="light")
    args = parser.parse_args()
    train_final(force_reload=args.force_reload, profile=args.profile)
