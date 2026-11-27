"""Repeatable session-disjoint CICIDS baseline; never reads frozen holdout rows."""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split

BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.evaluation.holdout import (  # noqa: E402
    MANIFEST_PATH, DATASET_VERSION, load_and_validate_manifest, manifest_sha256,
)
from ml.evaluation.open_set_pipeline import evaluate_one_family  # noqa: E402
from ml.evaluation.output_paths import get_results_dir  # noqa: E402
from ml.preprocessing.cicids_pipeline import (  # noqa: E402
    ATTACK_FAMILIES, CICIDS_FILES, DATASETS_DIR, LABEL_COL, HostWindowAggregator,
    _get_feature_cols, _hash_sample_mask, _load_one_csv, add_protocol_invariant_features,
    deduplicate_flows, enrich_flow_with_host_context, get_data_hash,
)


SEEDS = (42, 101, 202, 303, 404)
SAMPLE_FRACTION = 0.15
TRAIN_ROW_CAP = 60_000
CLASSIFIER_ESTIMATORS = 80
THRESHOLD_PERCENTILE = 95.0
ROW_BOOTSTRAP_RESAMPLES = 2000
SEED_BOOTSTRAP_RESAMPLES = 10_000


def load_development_frame(manifest: dict, sample: float = SAMPLE_FRACTION) -> pd.DataFrame:
    """Load only development source CSVs; holdout CSV rows are never parsed."""
    allowed = set(manifest["development_source_files"])
    if allowed & set(manifest["holdout_source_files"]):
        raise ValueError("Frozen holdout group overlaps development groups")
    parts = []
    for filename in CICIDS_FILES:
        if filename not in allowed:
            continue
        frame = _load_one_csv(DATASETS_DIR / "trafficlabelling" / filename)
        frame["_source_file"] = filename
        if sample < 1:
            mask = _hash_sample_mask(frame, sample)
            frame = frame.iloc[np.flatnonzero(mask)]
        parts.append(frame)
        print(f"[development source loaded] {filename}: {len(frame):,} sampled rows")
    if not parts:
        raise ValueError("Frozen manifest contains no development data")
    development = pd.concat(parts, ignore_index=True)
    del parts
    development, exact_dropped, conflicts_dropped = deduplicate_flows(development)
    if set(development["_source_file"].unique()) & set(manifest["holdout_source_files"]):
        raise AssertionError("Frozen holdout rows entered the development frame")
    if "Timestamp" in development.columns:
        raise ValueError("Dataset revision has timestamps; freeze a new explicit session-grouping policy")
    print(f"[development deduplicated] rows={len(development):,}; exact={exact_dropped:,}; conflicts={conflicts_dropped:,}")
    return development.reset_index(drop=True)


def build_family_fold(frame: pd.DataFrame, family: str, seed: int,
                      holdout_files: list[str]) -> tuple[dict, dict]:
    """Build train/validation/test by whole source-session groups for one LOFO family."""
    if family not in ATTACK_FAMILIES:
        raise ValueError(f"Unknown attack family: {family}")
    if set(frame["_source_file"].unique()) & set(holdout_files):
        raise AssertionError("Frozen holdout group is present in evaluation input")

    test_groups = sorted(frame.loc[frame[LABEL_COL] == family, "_source_file"].astype(str).unique())
    if not test_groups:
        raise ValueError(f"No development capture session contains family {family}")
    test_mask = frame["_source_file"].isin(test_groups)
    test = frame.loc[test_mask].copy()
    candidate = frame.loc[~test_mask & (frame[LABEL_COL] != family)].copy()
    candidate_groups = sorted(candidate["_source_file"].astype(str).unique())
    if len(candidate_groups) < 2:
        raise ValueError(f"Not enough independent development sessions to train/validate {family}")

    splitter = GroupShuffleSplit(n_splits=1, test_size=1, random_state=int(seed))
    train_idx, val_idx = next(splitter.split(candidate, groups=candidate["_source_file"].astype(str)))
    train, validation = candidate.iloc[train_idx].copy(), candidate.iloc[val_idx].copy()
    train_groups = set(train["_source_file"].astype(str).unique())
    val_groups = set(validation["_source_file"].astype(str).unique())
    test_group_set = set(test_groups)
    if (train_groups & val_groups or train_groups & test_group_set or val_groups & test_group_set or
            test_group_set & set(holdout_files)):
        raise AssertionError("Source-session leakage detected in family fold")
    if (train[LABEL_COL] == family).any() or (validation[LABEL_COL] == family).any():
        raise AssertionError("Held-out family leaked into model training or validation")

    train_cap = min(TRAIN_ROW_CAP, len(train))
    if len(train) > train_cap:
        try:
            train, _ = train_test_split(train, train_size=train_cap, random_state=int(seed),
                                        stratify=train[LABEL_COL])
        except ValueError as exc:
            raise ValueError(f"Could not stratify the deterministic training cap for {family}: {exc}") from exc

    train = enrich_flow_with_host_context(train, HostWindowAggregator())
    validation = enrich_flow_with_host_context(validation, HostWindowAggregator())
    test = enrich_flow_with_host_context(test, HostWindowAggregator())
    for split in (train, validation, test):
        add_protocol_invariant_features(split, sanitize_session_features=True)
    feature_columns = _get_feature_cols(train, sanitize_session_features=True)
    if not feature_columns:
        raise ValueError("Session-invariant feature sanitization removed every feature")

    pipeline = {
        "train_df": train,
        "val_df": validation,
        "test_df": test,
        "feat_cols": feature_columns,
        "seed": int(seed),
        "attack_families": list(ATTACK_FAMILIES),
        "train_row_cap_per_fold": TRAIN_ROW_CAP,
        "classifier_estimators": CLASSIFIER_ESTIMATORS,
        "detectors": ["confidence"],
        "baseline_threshold_percentile": THRESHOLD_PERCENTILE,
        "include_binary_operating_metrics": True,
        "metric_bootstrap_resamples": ROW_BOOTSTRAP_RESAMPLES,
        "bootstrap_resamples": 200,
        "log1p": True,
    }
    split_details = {
        "family": family,
        "seed": int(seed),
        "train_source_sessions": sorted(train_groups),
        "validation_source_sessions": sorted(val_groups),
        "test_source_sessions": sorted(test_group_set),
        "rows": {"train": int(len(train)), "validation": int(len(validation)),
                 "test_session_total": int(len(test))},
        "validation_classes": sorted(validation[LABEL_COL].astype(str).unique().tolist()),
        "test_classes": sorted(test[LABEL_COL].astype(str).unique().tolist()),
    }
    return pipeline, split_details


def _seed_bootstrap_ci(values: list[float], seed: int) -> list[float | None]:
    if not values:
        return [None, None]
    array = np.asarray(values, dtype=np.float64)
    if len(array) == 1:
        return [float(array[0]), float(array[0])]
    rng = np.random.default_rng(seed)
    indexes = rng.integers(0, len(array), size=(SEED_BOOTSTRAP_RESAMPLES, len(array)))
    means = array[indexes].mean(axis=1)
    return [round(float(value), 6) for value in np.quantile(means, [0.025, 0.975])]


def _summarize_family(family: str, per_seed: list[dict]) -> dict:
    metric_names = ("precision", "recall", "f1", "oscr_auc", "known_macro_f1",
                    "fpr", "benign_replay_false_alert_rate")
    seed_values = {}
    for name in metric_names:
        values = [row["metrics"][name] for row in per_seed if row["metrics"][name] is not None]
        seed_values[name] = {
            "mean": round(float(np.mean(values)), 6) if values else None,
            "95CI_across_seeds": _seed_bootstrap_ci(values, seed=sum(ord(ch) for ch in family + name)),
            "values_by_seed": [
                {"seed": row["seed"], "value": row["metrics"][name]}
                for row in per_seed if row["metrics"][name] is not None
            ],
        }
    classification = {}
    for split_name in ("train", "validation", "known_test"):
        split_runs = [row["classifier_metrics"][split_name] for row in per_seed]
        aggregate = {}
        for metric_name in ("macro_precision", "macro_recall", "macro_f1", "macro_auprc",
                            "cohen_kappa", "mcc"):
            values = [run[metric_name] for run in split_runs if run[metric_name] is not None]
            aggregate[metric_name] = {
                "mean": round(float(np.mean(values)), 6) if values else None,
                "95CI_across_seeds": _seed_bootstrap_ci(
                    values, seed=sum(ord(ch) for ch in family + split_name + metric_name)
                ),
                "values_by_seed": [
                    {"seed": row["seed"], "value": row["classifier_metrics"][split_name][metric_name]}
                    for row in per_seed
                    if row["classifier_metrics"][split_name][metric_name] is not None
                ],
            }
        classes = sorted({name for run in split_runs for name in run["per_class"]})
        per_class = {}
        for class_name in classes:
            per_class[class_name] = {}
            for metric_name in ("precision", "recall", "f1", "auprc"):
                values = [run["per_class"][class_name][metric_name] for run in split_runs
                          if class_name in run["per_class"] and run["per_class"][class_name][metric_name] is not None]
                per_class[class_name][metric_name] = {
                    "mean": round(float(np.mean(values)), 6) if values else None,
                    "95CI_across_seeds": _seed_bootstrap_ci(
                        values, seed=sum(ord(ch) for ch in family + split_name + class_name + metric_name)
                    ),
                    "values_by_seed": [
                        {"seed": row["seed"], "value": (
                            row["classifier_metrics"][split_name]["per_class"].get(class_name, {}).get(metric_name)
                        )}
                        for row in per_seed
                    ],
                }
            per_class[class_name]["support_by_seed"] = [
                {"seed": row["seed"], "value": (
                    row["classifier_metrics"][split_name]["per_class"].get(class_name, {}).get("support")
                )}
                for row in per_seed
            ]
        classification[split_name] = {"metrics": aggregate, "per_class": per_class}

    return {
        "family": family,
        "test_source_sessions": sorted({group for row in per_seed for group in row["split"]["test_source_sessions"]}),
        "seed_runs": per_seed,
        "metrics": seed_values,
        "classifier_metrics": classification,
    }


def _processed_dev_hash(frame: pd.DataFrame) -> str:
    values = pd.util.hash_pandas_object(frame, index=False).to_numpy(dtype=np.uint64, copy=False)
    return hashlib.sha256(values.tobytes()).hexdigest()


def run_network_baseline(*, sample: float = SAMPLE_FRACTION,
                         seeds: tuple[int, ...] = SEEDS,
                         manifest_path: Path = MANIFEST_PATH) -> dict:
    if tuple(seeds) != SEEDS:
        raise ValueError(f"Baseline seeds are frozen to {list(SEEDS)}")
    if sample != SAMPLE_FRACTION:
        raise ValueError(f"Baseline sample fraction is frozen to {SAMPLE_FRACTION}")
    manifest = load_and_validate_manifest(manifest_path)
    development = load_development_frame(manifest, sample=sample)
    missing_families = sorted(set(ATTACK_FAMILIES) - set(development[LABEL_COL].astype(str).unique()))
    if missing_families:
        raise ValueError(f"Development data lacks attack families required for baseline: {missing_families}")

    run_time = datetime.now(timezone.utc)
    run_id = run_time.strftime("%Y%m%dT%H%M%SZ")
    results_dir = get_results_dir(test_mode=False)
    results_dir.mkdir(parents=True, exist_ok=True)
    output = results_dir / f"network_baseline_{run_id}.json"
    partial = results_dir / f"network_baseline_{run_id}.partial.json"
    if output.exists() or partial.exists():
        raise FileExistsError(f"Refusing to overwrite an existing baseline artifact for run {run_id}")

    per_family = []
    payload = {
        "artifact_schema_version": 3,
        "run_id": run_id,
        "created_at_utc": run_time.isoformat(),
        "dataset": {
            "version": manifest["dataset_version"],
            "sha256": manifest["dataset_sha256"],
            "processed_development_sample_sha256": _processed_dev_hash(development),
            "sample_fraction": sample,
            "sample_method": "stable feature-row hash modulo 100, threshold 15; applied only to development source sessions",
            "source_file_sha256": manifest["source_files"],
        },
        "holdout": {
            "manifest_path": str(manifest_path.relative_to(REPO)).replace("\\", "/"),
            "manifest_sha256": manifest_sha256(manifest_path),
            "source_sessions": manifest["holdout_source_files"],
            "status": "frozen and untouched; no holdout rows were parsed or used for fitting, calibration, or scoring",
        },
        "split_rules": {
            "session_unit": "complete source CSV capture session; CICIDS2017 source files have no Timestamp column",
            "development_test": "for each family, every development source session containing that family is held out as test; those sessions are excluded from train and validation",
            "development_validation": "one complete non-test source session is selected by GroupShuffleSplit using the recorded seed",
            "training": "all other development sessions; held-out-family rows are removed from train and validation; scaling and thresholds use training/validation only",
            "unknown_test_population": "target-family rows in that family’s reserved development test sessions",
            "known_test_population": "non-target test rows whose labels occur in that fold’s training data; other unseen labels are excluded and counted",
        },
        "model_and_decision_policy": {
            "classifier": "LightGBM multiclass with current repository class weights",
            "detector": "confidence-only open-set score (1 - maximum class probability)",
            "threshold": "95th percentile of known-only validation scores",
            "feature_policy": "session-invariant sanitization enabled; scaler fitted on training rows only",
            "host_window_context": "CICIDS source data has no timestamps; host-window features therefore remain zero in this baseline",
            "train_row_cap_per_family_fold": TRAIN_ROW_CAP,
            "classifier_estimators": CLASSIFIER_ESTIMATORS,
            "random_seeds": list(seeds),
            "bootstrap": {
                "per_seed": "stratified row bootstrap of binary decisions with known/unknown/benign supports fixed",
                "across_seeds": "percentile bootstrap of seed-level metric means",
                "per_seed_resamples": ROW_BOOTSTRAP_RESAMPLES,
                "across_seed_resamples": SEED_BOOTSTRAP_RESAMPLES,
            },
        },
        "metric_definitions": {
            "precision": "unknown-family true positives divided by all unknown-review flags",
            "recall": "unknown-family rows flagged for unknown review divided by all target-family test rows",
            "f1": "harmonic mean of unknown-review precision and recall",
            "fpr": "known-class test rows incorrectly flagged for unknown review divided by eligible known-class test rows",
            "benign_replay_false_alert_rate": "BENIGN rows from held-out development capture sessions incorrectly flagged for unknown review divided by BENIGN rows in those sessions; this is an offline session replay metric, not a live-service replay run",
            "unknown_review_semantics": "confidence-threshold rejection is a triage proxy for UNKNOWN_NOVEL review, not a confirmed attack verdict",
            "classifier_metrics": "For each family/seed fold, per-class one-vs-rest precision, recall, F1, and average precision (AUPRC), plus macro summaries, Cohen's kappa, and MCC are reported on train, known-only validation, and known-only test. Train values are in-sample diagnostics, not generalization estimates. Unknown-family test rows are excluded from closed-set classifier metrics and remain evaluated by the open-set metrics. Macro AUPRC averages classes with positive support; unsupported class AUPRC is null.",
        },
        "seeds": list(seeds),
        "families": [],
    }

    for family in ATTACK_FAMILIES:
        family_runs = []
        for seed in seeds:
            pipeline, split = build_family_fold(
                development, family, seed, manifest["holdout_source_files"]
            )
            result = evaluate_one_family(family, pipeline)
            if "detectors" not in result:
                raise RuntimeError(f"Baseline fold skipped for {family}/seed {seed}: {result.get('skipped')}")
            detector = result["detectors"]["confidence"]
            operating = detector.get("operating_metrics")
            if not operating:
                raise RuntimeError(f"Missing binary metrics for {family}/seed {seed}")
            family_runs.append({
                "seed": seed,
                "split": split,
                "metrics": {
                    **{name: operating[name] for name in (
                        "precision", "recall", "f1", "fpr", "benign_replay_false_alert_rate"
                    )},
                    "oscr_auc": detector["oscr_auc"],
                    "known_macro_f1": detector["known_macro_f1"],
                },
                "classifier_metrics": result["classifier_metrics"],
                "bootstrap_95CI": operating["bootstrap_95CI"],
                "support": operating["support"],
                "decision": {
                    "threshold_value": detector["threshold_value"],
                    "threshold_percentile": detector["threshold_percentile"],
                    "known_macro_f1": detector["known_macro_f1"],
                    "oscr_auc": detector["oscr_auc"],
                    "auroc": detector["AUROC"],
                    "auprc": detector["auprc"],
                },
                "excluded_test_rows_without_training_class": result.get(
                    "excluded_test_rows_without_training_class", {}
                ),
            })
            print(f"[baseline fold complete] family={family} seed={seed} "
                  f"recall={operating['recall']:.4f} precision={operating['precision']:.4f} "
                  f"fpr={operating['fpr']:.4f}")
            current = _summarize_family(family, family_runs)
            payload["families"] = [*payload["families"], current] if not any(
                item["family"] == family for item in payload["families"]
            ) else [current if item["family"] == family else item for item in payload["families"]]
            partial.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        payload["families"] = [
            _summarize_family(family, family_runs) if item["family"] == family else item
            for item in payload["families"]
        ]

    payload["run_status"] = "complete"
    payload["development_row_count"] = int(len(development))
    payload["development_source_sessions"] = manifest["development_source_files"]
    payload["split_integrity"] = "passed; train/validation/test source groups are pairwise disjoint for every family and seed"
    output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    partial.unlink(missing_ok=True)
    return {"artifact": output, "payload": payload}


if __name__ == "__main__":
    result = run_network_baseline()
    print(f"Saved baseline artifact: {result['artifact']}")
