"""
Step C (measurement only) — Binary attack-vs-benign leave-one-capture-day-out evaluation.

Protocol
--------
- Label every non-BENIGN row as attack (positive); BENIGN rows are negative.
- Group the CICIDS2017 development capture files by calendar day:
    Tuesday  : Tuesday-WorkingHours.pcap_ISCX.csv
    Wednesday: Wednesday-workingHours.pcap_ISCX.csv
    Thursday : Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
               + Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv  (benign-only)
    Friday   : Friday-WorkingHours-Morning.pcap_ISCX.csv
               + Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
               + Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  Yielding 4 held-out day units (Tue, Wed, Thu, Fri).
- Monday (Monday-WorkingHours.pcap_ISCX.csv) is the frozen reserved holdout and is
  NEVER loaded or evaluated here.
- For each held-out day unit:
    Train : all development files NOT belonging to that day.
    Fit   : LightGBM multiclass on the full multi-class label (unchanged from baseline).
    Score : confidence-only binary score = 1 - P(BENIGN), applied to held-out day rows.
    Threshold: 95th percentile of training BENIGN rows' binary scores (conservative,
              identical to the per-family threshold policy).
  No model weights, hyperparameters, splits, thresholds, or feature sets are changed.
- Aggregate: paired bootstrap over 4 held-out capture-day units (10,000 resamples).
- Per-family recall on each held-out day is recorded as descriptive only (n=1 per family).
- The frozen Monday holdout is excluded; its SHA-256 is verified but its rows are never
  read for scoring or fitting.

Outputs
-------
  backend/ml/evaluation/results/locd_binary_eval_<run_id>.json  — full artifact
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

BACKEND = Path(__file__).resolve().parents[1] / "backend"
REPO = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.evaluation.holdout import (  # noqa: E402
    MANIFEST_PATH, load_and_validate_manifest, manifest_sha256,
)
from ml.evaluation.output_paths import get_results_dir  # noqa: E402
from ml.preprocessing.cicids_pipeline import (  # noqa: E402
    ATTACK_FAMILIES, CICIDS_FILES, DATASETS_DIR, LABEL_COL, HostWindowAggregator,
    _get_feature_cols, _hash_sample_mask, _load_one_csv, add_protocol_invariant_features,
    deduplicate_flows, enrich_flow_with_host_context,
)

# ---------------------------------------------------------------------------
# Constants — frozen; do not change without protocol amendment
# ---------------------------------------------------------------------------
SAMPLE_FRACTION = 0.15          # identical to network_baseline.py
TRAIN_ROW_CAP = 60_000          # identical to network_baseline.py
CLASSIFIER_ESTIMATORS = 80      # identical to network_baseline.py
THRESHOLD_PERCENTILE = 95.0     # identical to network_baseline.py
BOOTSTRAP_RESAMPLES = 10_000    # paired capture-day bootstrap
BOOTSTRAP_SEED = 20261127       # fixed for reproducibility

# Map each development CSV to its calendar day label.
# Thursday Afternoon Infilteration is benign-only in the development scope
# (Infiltration is excluded from ATTACK_FAMILIES); we include it in Thursday
# so all Thursday files stay out of training when Thursday is held out.
DAY_ASSIGNMENT: dict[str, str] = {
    "Tuesday-WorkingHours.pcap_ISCX.csv":                       "Tuesday",
    "Wednesday-workingHours.pcap_ISCX.csv":                     "Wednesday",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv":   "Thursday",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "Thursday",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv":                "Friday",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv":     "Friday",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv":         "Friday",
}
# Monday is the frozen holdout — must never appear in DAY_ASSIGNMENT
HOLDOUT_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
# Attack families present on each day (ground truth from protocol doc)
FAMILIES_BY_DAY: dict[str, list[str]] = {
    "Tuesday":   ["BruteForce"],
    "Wednesday": ["DosDDoS"],
    "Thursday":  ["WebAttack"],
    "Friday":    ["Bot", "PortScan", "DosDDoS"],
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_development_frame(manifest: dict) -> pd.DataFrame:
    """Load all development source CSVs (15% sample); never touches holdout file."""
    allowed = set(manifest["development_source_files"])
    if allowed & set(manifest["holdout_source_files"]):
        raise ValueError("Frozen holdout group overlaps development groups")

    parts = []
    for filename in CICIDS_FILES:
        if filename not in allowed:
            continue
        frame = _load_one_csv(DATASETS_DIR / "trafficlabelling" / filename)
        frame["_source_file"] = filename
        frame["_capture_day"] = DAY_ASSIGNMENT.get(filename, "UNKNOWN")
        mask = _hash_sample_mask(frame, SAMPLE_FRACTION)
        frame = frame.iloc[np.flatnonzero(mask)]
        parts.append(frame)
        print(f"[locd] loaded {filename}: {len(frame):,} sampled rows")

    if not parts:
        raise ValueError("No development data found")
    dev = pd.concat(parts, ignore_index=True)
    del parts
    dev, exact, conflicts = deduplicate_flows(dev)
    if set(dev["_source_file"].unique()) & set(manifest["holdout_source_files"]):
        raise AssertionError("Frozen holdout rows entered the development frame")
    if "Timestamp" in dev.columns:
        raise ValueError("Dataset revision has timestamps; review session-grouping policy")
    print(f"[locd] development rows={len(dev):,}; exact_dropped={exact:,}; conflicts={conflicts:,}")
    return dev.reset_index(drop=True)


def _make_binary(label_series: pd.Series) -> pd.Series:
    """Map BENIGN -> 0 (negative), everything else -> 1 (attack/positive)."""
    return (label_series != "BENIGN").astype(int)


def _fit_lgbm(x_train: np.ndarray, y_train_multiclass: pd.Series,
              classes: list[str], seed: int):
    """Fit a LightGBM multiclass classifier; return fitted model and class order."""
    try:
        import lightgbm as lgb
    except ImportError as exc:
        raise ImportError("lightgbm is required for LOCD evaluation") from exc

    n_classes = len(classes)
    if n_classes < 2:
        raise ValueError(f"Training data has fewer than 2 classes: {classes}")

    class_counts = y_train_multiclass.value_counts()
    # Inverse-frequency weights matching baseline class weight policy
    weights_map = {cls: 1.0 / max(class_counts.get(cls, 1), 1) for cls in classes}
    sample_weight = y_train_multiclass.map(weights_map).fillna(1.0).to_numpy(dtype=np.float64)

    objective = "multiclass" if n_classes > 2 else "binary"
    model = lgb.LGBMClassifier(
        n_estimators=CLASSIFIER_ESTIMATORS,
        objective=objective,
        num_class=n_classes if n_classes > 2 else None,
        random_state=seed,
        verbose=-1,
        n_jobs=-1,
    )
    model.fit(x_train, y_train_multiclass, sample_weight=sample_weight)
    return model, classes


def _binary_score(model, x: np.ndarray, benign_class_idx: int) -> np.ndarray:
    """Return 1 - P(BENIGN) as the attack confidence score."""
    proba = model.predict_proba(x)
    if proba.ndim == 1:
        # Binary LightGBM returns P(positive) directly
        return proba
    return 1.0 - proba[:, benign_class_idx]


def _operating_metrics(y_true_binary: np.ndarray,
                       scores: np.ndarray,
                       threshold: float) -> dict:
    preds = (scores >= threshold).astype(int)
    tp = int(((preds == 1) & (y_true_binary == 1)).sum())
    fp = int(((preds == 1) & (y_true_binary == 0)).sum())
    tn = int(((preds == 0) & (y_true_binary == 0)).sum())
    fn = int(((preds == 0) & (y_true_binary == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) > 0
          else None)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "support_positive": int(y_true_binary.sum()),
        "support_negative": int((1 - y_true_binary).sum()),
        "total": int(len(y_true_binary)),
    }


def _auprc(y_true: np.ndarray, scores: np.ndarray) -> float | None:
    try:
        from sklearn.metrics import average_precision_score
        if y_true.sum() == 0 or y_true.sum() == len(y_true):
            return None
        return float(average_precision_score(y_true, scores))
    except Exception:
        return None


def _per_family_recall(test_df: pd.DataFrame, scores: np.ndarray,
                       threshold: float) -> dict[str, dict]:
    """Descriptive per-family recall on the held-out day rows (n=1 day)."""
    preds = (scores >= threshold).astype(int)
    out: dict[str, dict] = {}
    for family in ATTACK_FAMILIES:
        mask = (test_df[LABEL_COL] == family).to_numpy()
        n = int(mask.sum())
        if n == 0:
            out[family] = {"n": 0, "recall": None, "tp": 0, "fn": 0,
                           "note": "no rows for this family on this day"}
        else:
            tp = int(preds[mask].sum())
            fn = n - tp
            out[family] = {
                "n": n, "tp": tp, "fn": fn,
                "recall": tp / n,
                "note": "descriptive, n=1 capture day unit",
            }
    return out


def _paired_day_bootstrap(day_metrics: list[dict],
                          key: str, seed: int) -> dict:
    """
    Paired bootstrap over held-out capture-day units.
    Resample the list of day-level metric values with replacement.
    Returns mean, 95% CI lower, upper.
    """
    values = [d[key] for d in day_metrics if d.get(key) is not None]
    n = len(values)
    if n == 0:
        return {"mean": None, "ci95_lo": None, "ci95_hi": None, "n_days": 0}
    arr = np.asarray(values, dtype=np.float64)
    if n == 1:
        return {"mean": float(arr[0]), "ci95_lo": float(arr[0]),
                "ci95_hi": float(arr[0]), "n_days": 1,
                "note": "n=1 day; CI is degenerate (single observation)"}
    rng = np.random.default_rng(seed + sum(ord(c) for c in key))
    idx = rng.integers(0, n, size=(BOOTSTRAP_RESAMPLES, n))
    boot_means = arr[idx].mean(axis=1)
    lo, hi = float(np.quantile(boot_means, 0.025)), float(np.quantile(boot_means, 0.975))
    return {"mean": float(arr.mean()), "ci95_lo": lo, "ci95_hi": hi, "n_days": n}


def run_locd_eval(manifest_path: Path = MANIFEST_PATH) -> dict:
    """Run the full leave-one-capture-day-out binary evaluation and save a JSON artifact."""
    manifest = load_and_validate_manifest(manifest_path)
    dev = load_development_frame(manifest)

    # Verify holdout file is completely absent from loaded data
    if HOLDOUT_FILE in dev["_source_file"].unique():
        raise AssertionError(f"Frozen holdout file {HOLDOUT_FILE!r} present in development frame")

    days = sorted(dev["_capture_day"].unique())
    if set(days) != {"Tuesday", "Wednesday", "Thursday", "Friday"}:
        raise ValueError(f"Unexpected capture day set in development data: {days}")

    run_time = datetime.now(timezone.utc)
    run_id = run_time.strftime("%Y%m%dT%H%M%SZ")
    results_dir = get_results_dir(test_mode=False)
    results_dir.mkdir(parents=True, exist_ok=True)
    output = results_dir / f"locd_binary_eval_{run_id}.json"
    partial = results_dir / f"locd_binary_eval_{run_id}.partial.json"

    day_results: list[dict] = []

    for held_out_day in ["Tuesday", "Wednesday", "Thursday", "Friday"]:
        print(f"\n[locd] === held-out day: {held_out_day} ===")
        test_df = dev[dev["_capture_day"] == held_out_day].copy()
        train_df = dev[dev["_capture_day"] != held_out_day].copy()

        # Sanity: no cross-day leakage
        if set(test_df["_capture_day"].unique()) & set(train_df["_capture_day"].unique()):
            raise AssertionError(f"Day-level leakage for {held_out_day}")

        # Feature enrichment (identical to baseline; host-window stays zero)
        agg = HostWindowAggregator()
        train_df = enrich_flow_with_host_context(train_df, agg)
        test_df = enrich_flow_with_host_context(test_df, HostWindowAggregator())
        for split in (train_df, test_df):
            add_protocol_invariant_features(split, sanitize_session_features=True)
        feat_cols = _get_feature_cols(train_df, sanitize_session_features=True)
        if not feat_cols:
            raise ValueError(f"No features left after sanitization for day {held_out_day}")

        # Cap training rows (same policy as baseline)
        if len(train_df) > TRAIN_ROW_CAP:
            try:
                train_df, _ = train_test_split(
                    train_df, train_size=TRAIN_ROW_CAP, random_state=BOOTSTRAP_SEED,
                    stratify=train_df[LABEL_COL],
                )
            except ValueError:
                train_df = train_df.sample(TRAIN_ROW_CAP, random_state=BOOTSTRAP_SEED)

        x_train = train_df[feat_cols].to_numpy(dtype=np.float32)
        x_test = test_df[feat_cols].to_numpy(dtype=np.float32)
        y_train_multi = train_df[LABEL_COL].astype(str)
        train_classes = sorted(y_train_multi.unique())

        print(f"[locd] train rows={len(train_df):,}  classes={train_classes}")
        print(f"[locd] test  rows={len(test_df):,}   day families present: "
              f"{sorted(test_df[LABEL_COL].unique())}")

        model, fitted_classes = _fit_lgbm(x_train, y_train_multi, train_classes,
                                          seed=BOOTSTRAP_SEED)
        benign_idx = fitted_classes.index("BENIGN") if "BENIGN" in fitted_classes else 0

        # Threshold: 95th percentile of training BENIGN rows' scores
        benign_train_mask = (y_train_multi == "BENIGN").to_numpy()
        x_train_benign = x_train[benign_train_mask]
        threshold_scores = _binary_score(model, x_train_benign, benign_idx)
        threshold = float(np.percentile(threshold_scores, THRESHOLD_PERCENTILE))
        print(f"[locd] threshold={threshold:.6f} (p{THRESHOLD_PERCENTILE:.0f} of train BENIGN scores)")

        # Score test set
        test_scores = _binary_score(model, x_test, benign_idx)
        y_test_binary = _make_binary(test_df[LABEL_COL]).to_numpy()

        ops = _operating_metrics(y_test_binary, test_scores, threshold)
        auprc_val = _auprc(y_test_binary, test_scores)
        per_family = _per_family_recall(test_df, test_scores, threshold)

        # Attack-class label distribution in test
        test_label_dist = {
            str(k): int(v) for k, v in test_df[LABEL_COL].value_counts().items()
        }

        day_result = {
            "held_out_day": held_out_day,
            "held_out_files": sorted(
                test_df["_source_file"].unique().tolist()
            ),
            "train_files": sorted(train_df["_source_file"].unique().tolist()),
            "train_rows": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "test_label_distribution": test_label_dist,
            "threshold": threshold,
            "threshold_rule": f"p{THRESHOLD_PERCENTILE:.0f} of training BENIGN row scores",
            "binary_operating_metrics": ops,
            "binary_auprc": auprc_val,
            "per_family_recall_descriptive": per_family,
            "families_on_day_per_protocol": FAMILIES_BY_DAY.get(held_out_day, []),
        }
        day_results.append(day_result)
        print(f"[locd] {held_out_day}: precision={ops['precision']}, "
              f"recall={ops['recall']}, f1={ops['f1']}, auprc={auprc_val}")

        partial.write_text(
            json.dumps({"run_id": run_id, "partial": True,
                        "completed_days": [r["held_out_day"] for r in day_results],
                        "day_results": day_results}, indent=2),
            encoding="utf-8",
        )

    # Aggregate across days via paired bootstrap
    agg_metrics: dict[str, dict] = {}
    for metric in ("precision", "recall", "f1", "fpr", "binary_auprc"):
        if metric == "binary_auprc":
            vals = [{metric: r.get("binary_auprc")} for r in day_results]
        else:
            vals = [{metric: r["binary_operating_metrics"].get(metric)} for r in day_results]
        agg_metrics[metric] = _paired_day_bootstrap(vals, metric, BOOTSTRAP_SEED)

    payload = {
        "artifact_schema_version": 1,
        "artifact_type": "locd_binary_eval",
        "run_id": run_id,
        "run_status": "complete",
        "created_at_utc": run_time.isoformat(),
        "protocol": {
            "name": "binary attack-vs-benign leave-one-capture-day-out",
            "scope": "CICIDS2017 development scope (4 held-out day units: Tue, Wed, Thu, Fri)",
            "holdout_excluded": HOLDOUT_FILE,
            "positive_class": "any non-BENIGN label",
            "negative_class": "BENIGN",
            "threshold_rule": f"p{THRESHOLD_PERCENTILE:.0f} of training BENIGN row scores (default threshold, unchanged)",
            "model": "LightGBM multiclass; current repository class weights; no config change",
            "feature_policy": "session-invariant sanitization; host-window features remain zero (no Timestamp/Source IP)",
            "sample_fraction": SAMPLE_FRACTION,
            "train_row_cap": TRAIN_ROW_CAP,
            "per_family_recall_note": "descriptive only, n=1 capture day unit per family; not used for any accept/reject decision",
            "bootstrap": {
                "type": "paired over held-out capture-day units",
                "resamples": BOOTSTRAP_RESAMPLES,
                "seed": BOOTSTRAP_SEED,
            },
            "step_c_constraints": [
                "no model change",
                "no training/split change",
                "no threshold tuning",
                "no feature engineering change",
                "Monday holdout file never loaded",
            ],
        },
        "dataset": {
            "version": manifest["dataset_version"],
            "sha256": manifest["dataset_sha256"],
            "sample_fraction": SAMPLE_FRACTION,
        },
        "holdout": {
            "file": HOLDOUT_FILE,
            "manifest_sha256": manifest_sha256(manifest_path),
            "status": "frozen and untouched; never loaded for scoring or fitting",
        },
        "day_units": days,
        "n_day_units": len(day_results),
        "day_results": day_results,
        "aggregate_metrics_paired_day_bootstrap": agg_metrics,
    }

    output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    partial.unlink(missing_ok=True)
    print(f"\n[locd] Saved artifact: {output}")
    return {"artifact": output, "payload": payload}


if __name__ == "__main__":
    result = run_locd_eval()
    agg = result["payload"]["aggregate_metrics_paired_day_bootstrap"]
    print(f"\n=== Aggregate binary attack-vs-benign LOCD results (n=4 day units) ===")
    for metric, stats in agg.items():
        mean = f"{stats['mean']:.4f}" if stats["mean"] is not None else "n/a"
        lo = f"{stats['ci95_lo']:.4f}" if stats["ci95_lo"] is not None else "n/a"
        hi = f"{stats['ci95_hi']:.4f}" if stats["ci95_hi"] is not None else "n/a"
        print(f"  {metric:15s}: {mean}  95% CI [{lo}, {hi}]  (n={stats['n_days']} days)")
