"""
Master CICIDS2017 Evaluation Runner
=====================================
Run this script to execute the full pipeline end-to-end:
  1. Load + clean + cache all 8 CICIDS2017 CSVs
  2. Stratified 70/10/20 split per file
  3. Train LightGBM + XGBoost known-class classifiers
  4. Leave-one-family-out open-set evaluation (5 families × 4 detectors)
  5. Save all results to backend/ml/evaluation/results/

Usage:
  cd d:/MAJOR PROJECT
  python backend/ml/run_cicids_eval.py

  # Force reload of parquet cache (re-reads CSVs):
  python backend/ml/run_cicids_eval.py --force-reload

Results JSON files are read by the FastAPI endpoint /api/evaluation/results
and displayed in the frontend DataManagement page — never hardcoded.
"""

from __future__ import annotations

import argparse
import gc
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.preprocessing.cicids_pipeline import build_full_pipeline
from ml.evaluation.known_classifier import run_known_classifier
from ml.evaluation.open_set_pipeline import run_open_set_evaluation

LIGHT_DETECTORS = [
    "confidence", "isolation_forest", "mahalanobis",
    "confidence_mahalanobis_rank_average",
]


def _git_revision() -> tuple[str | None, str | None]:
    try:
        value = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2],
            stderr=subprocess.DEVNULL, text=True,
        ).strip()
        return value, None
    except (OSError, subprocess.CalledProcessError):
        return None, "unavailable: workspace is not a git worktree"


def main():
    parser = argparse.ArgumentParser(description="CICIDS2017 Full Evaluation Pipeline")
    parser.add_argument("--profile", choices=["full", "light"], default="full")
    parser.add_argument("--force-reload", action="store_true",
                        help="Re-read CSVs and rebuild Parquet cache")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--sample", type=float,
                        help="Stratified fraction of cleaned rows to evaluate (0 < fraction <= 1)")
    parser.add_argument("--run-id", help="Stable ID used for per-family partial checkpoints and resume")
    parser.add_argument("--log1p", action="store_true",
                        help="Apply train-fitted log1p to features that are non-negative in train")
    args = parser.parse_args()

    print("=" * 70)
    print("ENTERPRISE CYBERGUARD X — CICIDS2017 Evaluation Pipeline")
    print("=" * 70)

    # ── Stage 1: Data ──────────────────────────────────────────────────────
    print("\n[Stage 1] Loading and preprocessing CICIDS2017 ...")
    light = args.profile == "light"
    seed = args.seed if args.seed is not None else 42
    sample = args.sample if args.sample is not None else (0.15 if light else 1.0)
    if light and (seed != 42 or sample != 0.15):
        parser.error("--profile light fixes --seed 42 and --sample 0.15")
    log1p = True if light else args.log1p
    run_id = args.run_id or f"{args.profile}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    git_hash, git_hash_status = _git_revision()
    profile_config = {
        "profile_name": args.profile,
        "sample_fraction": sample,
        "train_row_cap_per_fold": 60000 if light else None,
        "bootstrap_resamples": 200 if light else 1000,
        "detectors": LIGHT_DETECTORS if light else ["confidence", "isolation_forest", "autoencoder", "mahalanobis", "mahalanobis_mlp", "confidence_mahalanobis_rank_average"],
        "known_classifier_models": ["LightGBM"] if light else ["LightGBM", "XGBoost"],
        "isolation_forest": {"n_estimators": 100, "max_samples": 10000, "n_jobs": -1} if light else {"n_estimators": 200, "max_samples": "auto", "n_jobs": -1},
        "flags": {"log1p": log1p, "xgboost": not light, "reduced_profile": light,
                  "stratified_random_split": True},
        "git_hash": git_hash,
        "git_hash_status": git_hash_status,
        "reduced_profile_warning": "Results are from a reduced profile on a stratified random split." if light else None,
    }
    pipeline = build_full_pipeline(force_reload=args.force_reload, seed=seed,
                                   sample=sample, log1p=log1p)
    pipeline.update(profile_config)
    pipeline["run_id"] = run_id
    pipeline["run_metadata"] = profile_config
    if light:
        print("WARNING: Results are from a reduced profile on a stratified random split.")
        print(f"Command: python backend/ml/run_cicids_eval.py --profile light --run-id {run_id}")
    print(f"WARNING: {pipeline['split_warning']}")

    # ── Stage 2: Known-class classifier ───────────────────────────────────
    print("\n[Stage 2] Training known-class classifiers ...")
    cls_results, lgbm_model, xgb_model = run_known_classifier(pipeline, include_xgboost=not light)
    del lgbm_model
    if xgb_model is not None:
        del xgb_model
    for key in ("X_train", "y_train", "X_val", "y_val", "X_test", "y_test", "scaler", "le", "full_df"):
        pipeline.pop(key, None)
    gc.collect()

    # ── Stage 3: Open-set evaluation ──────────────────────────────────────
    print("\n[Stage 3] Running leave-one-family-out open-set evaluation ...")
    os_results = run_open_set_evaluation(pipeline)

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Known classifier — LightGBM macro-F1: {cls_results['LightGBM']['macro_f1']:.4f}")
    if "XGBoost" in cls_results:
        print(f"Known classifier — XGBoost  macro-F1: {cls_results['XGBoost']['macro_f1']:.4f}")

    print("\nOpen-set macro-averages across all families:")
    for det, metrics in os_results["macro_average"].items():
        auroc = metrics.get("AUROC", "N/A")
        fpr   = metrics.get("FPR_at_95pct_TPR", "N/A")
        print(f"  {det:<20} AUROC={auroc}  FPR@95={fpr}")

    if os_results["warnings"]:
        print(f"\nWARNING: {len(os_results['warnings'])} weak/suspicious result(s) found:")
        for w in os_results["warnings"]:
            print(f"   {w}")
    else:
        print("\nAll open-set results look reasonable.")

    print(f"\nOpen-set result: {os_results['results_path']}")
    print(f"Partial checkpoint: backend/ml/evaluation/results/partial_{run_id}.json")


if __name__ == "__main__":
    main()

