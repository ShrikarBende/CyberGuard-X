"""Recompute and export the medium seed-42 BruteForce confidence fold only."""
from __future__ import annotations

import sys
import zlib
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.evaluation.open_set_pipeline import evaluate_one_family  # noqa: E402
from ml.preprocessing.cicids_pipeline import build_full_pipeline  # noqa: E402


def main() -> None:
    pipeline = build_full_pipeline(seed=42, sample=0.5, log1p=True)
    pipeline.update({
        "profile_name": "medium",
        "sample_fraction": 0.5,
        "train_row_cap_per_fold": 150_000,
        "bootstrap_resamples": 200,
        "detectors": ["confidence"],
        "save_detector_scores": True,
        "score_output_dir": Path(__file__).resolve().parent / "results" / "scores",
        "run_id": "cicids_medium_seed42",
    })
    result = evaluate_one_family("BruteForce", pipeline)
    detector = result["detectors"]["confidence"]
    scores_path = pipeline["score_output_dir"] / "cicids_medium_seed42_BruteForce.npz"
    with np.load(scores_path, allow_pickle=False) as saved:
        scores = saved["confidence_scores"].astype(np.float64)
        labels = saved["labels"]
    auroc = float(roc_auc_score(labels, scores))
    print(f"Recomputed AUROC: {auroc:.6f}")
    print(f"Saved medium AUROC: 0.980152")
    print(f"Score-bin AUROC interval: {detector['AUROC_95CI']}")
    print(f"Score rows: {len(scores)}; labels: known={(labels == 0).sum()}, unknown={(labels == 1).sum()}")
    print(f"Score artifact: {scores_path.resolve()}")
    if abs(auroc - 0.980152) > 0.001:
        raise SystemExit("AUROC mismatch exceeds 0.001; stopping before interval analysis and remaining steps.")

    # Resampling row indices within each class is the naive stratified row bootstrap.
    known_scores = scores[labels == 0]
    unknown_scores = scores[labels == 1]
    repetitions = 1000
    rng = np.random.default_rng(42 + zlib.crc32(b"BruteForce:confidence") % (2**31))
    _, bins = np.unique(scores, return_inverse=True)
    known_bins = bins[labels == 0]
    unknown_bins = bins[labels == 1]
    n_bins = int(bins.max()) + 1
    naive_aucs = np.empty(repetitions, dtype=np.float64)
    for index in range(repetitions):
        known_counts = np.bincount(
            rng.choice(known_bins, size=len(known_bins), replace=True), minlength=n_bins
        )
        unknown_counts = np.bincount(
            rng.choice(unknown_bins, size=len(unknown_bins), replace=True), minlength=n_bins
        )
        known_below = np.cumsum(known_counts) - known_counts
        wins = np.dot(unknown_counts, known_below + 0.5 * known_counts)
        naive_aucs[index] = wins / (len(known_bins) * len(unknown_bins))
    naive_interval = np.percentile(naive_aucs, [2.5, 97.5])
    score_bin_interval = np.asarray(detector["AUROC_95CI"], dtype=np.float64)
    print(f"Naive row-bootstrap AUROC interval (1000): {naive_interval.tolist()}")
    print(f"Naive row-bootstrap width: {naive_interval[1] - naive_interval[0]:.8f}")
    print(f"Score-bin width: {score_bin_interval[1] - score_bin_interval[0]:.8f}")
    auc = auroc
    n_known = len(known_scores)
    n_unknown = len(unknown_scores)
    q1 = auc / (2.0 - auc)
    q2 = 2.0 * auc * auc / (1.0 + auc)
    variance = (
        auc * (1.0 - auc)
        + (n_unknown - 1) * (q1 - auc * auc)
        + (n_known - 1) * (q2 - auc * auc)
    ) / (n_known * n_unknown)
    half_width = 1.959963984540054 * np.sqrt(max(variance, 0.0))
    analytic_interval = [max(0.0, auc - half_width), min(1.0, auc + half_width)]
    print(f"Hanley-McNeil AUROC interval: {analytic_interval}")
    print(f"Hanley-McNeil width: {analytic_interval[1] - analytic_interval[0]:.8f}")
    score_bin_width = score_bin_interval[1] - score_bin_interval[0]
    naive_width = naive_interval[1] - naive_interval[0]
    relative_difference = abs(score_bin_width - naive_width) / naive_width if naive_width else 0.0
    print(f"Score-bin vs naive relative width difference: {relative_difference:.2%}")


if __name__ == "__main__":
    main()
