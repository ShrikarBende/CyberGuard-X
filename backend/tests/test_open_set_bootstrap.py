"""Test score-bin AUROC bootstrap against a naive tied-score row bootstrap."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ml.evaluation.open_set_pipeline import bootstrap_metric_intervals


def test_score_bin_auc_bootstrap_matches_naive_stratified_row_bootstrap_width():
    # Deliberately small, discrete score support creates many tied observations.
    known_scores = np.repeat([0.0, 1.0, 2.0], [18, 9, 13])
    unknown_scores = np.repeat([0.0, 1.0, 2.0], [7, 12, 16])
    scores = np.concatenate([known_scores, unknown_scores])
    labels = np.concatenate([np.zeros(len(known_scores)), np.ones(len(unknown_scores))])
    seed = 731
    repetitions = 4000

    score_bin = bootstrap_metric_intervals(
        scores, labels, threshold=1.0, seed=seed, n_resamples=repetitions
    )["AUROC_95CI"]

    rng = np.random.default_rng(seed)
    naive_aucs = np.empty(repetitions)
    for index in range(repetitions):
        known = rng.choice(known_scores, size=len(known_scores), replace=True)
        unknown = rng.choice(unknown_scores, size=len(unknown_scores), replace=True)
        sample_scores = np.concatenate([known, unknown])
        sample_labels = np.concatenate([np.zeros(len(known)), np.ones(len(unknown))])
        naive_aucs[index] = roc_auc_score(sample_labels, sample_scores)
    naive_ci = np.percentile(naive_aucs, [2.5, 97.5])

    score_bin_width = score_bin[1] - score_bin[0]
    naive_width = naive_ci[1] - naive_ci[0]
    assert abs(score_bin_width - naive_width) <= 0.025
