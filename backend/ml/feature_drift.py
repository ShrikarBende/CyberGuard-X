"""PSI and two-sample KS checks for model-input batches."""
from __future__ import annotations

from typing import Sequence

import numpy as np
from scipy.stats import ks_2samp


def _psi(reference: np.ndarray, current: np.ndarray, bins: int = 10) -> float:
    quantiles = np.quantile(reference, np.linspace(0, 1, bins + 1))
    internal = np.unique(quantiles[1:-1])
    if np.ptp(reference) == 0:
        center = float(reference[0])
        epsilon = max(abs(center) * 1e-9, 1e-9)
        edges = np.asarray([-np.inf, center - epsilon, center + epsilon, np.inf])
    else:
        edges = np.concatenate(([-np.inf], internal, [np.inf]))
    expected = np.histogram(reference, bins=edges)[0].astype(np.float64) / len(reference)
    actual = np.histogram(current, bins=edges)[0].astype(np.float64) / len(current)
    expected = np.clip(expected, 1e-6, None)
    actual = np.clip(actual, 1e-6, None)
    return float(np.sum((actual - expected) * np.log(actual / expected)))


def monitor_feature_drift(reference: Sequence[Sequence[float]], current: Sequence[Sequence[float]],
                          feature_names: Sequence[str], *, psi_threshold: float | None = None) -> dict:
    """Compare a model's training reference with an input batch.

    PSI drives the configurable alert. KS statistic and p-value are reported as
    supporting per-feature distribution checks; they are not causal evidence.
    """
    ref = np.asarray(reference, dtype=np.float64)
    cur = np.asarray(current, dtype=np.float64)
    names = list(feature_names)
    if ref.ndim != 2 or cur.ndim != 2 or ref.shape[1] != len(names) or cur.shape[1] != len(names):
        raise ValueError("Drift matrices and feature names must have matching two-dimensional shapes")
    if len(ref) < 2 or len(cur) < 2:
        raise ValueError("PSI/KS drift monitoring requires at least two rows in each sample")
    if not np.isfinite(ref).all() or not np.isfinite(cur).all():
        raise ValueError("Drift samples must contain only finite values")
    if psi_threshold is None:
        from app.core.config import settings
        psi_threshold = settings.FEATURE_DRIFT_PSI_ALERT_THRESHOLD
    threshold = float(psi_threshold)
    if not np.isfinite(threshold) or threshold <= 0:
        raise ValueError("PSI alert threshold must be finite and positive")
    results = {}
    for index, name in enumerate(names):
        psi = _psi(ref[:, index], cur[:, index])
        ks = ks_2samp(ref[:, index], cur[:, index], alternative="two-sided", method="auto")
        results[name] = {"psi": psi, "ks_statistic": float(ks.statistic),
                         "ks_pvalue": float(ks.pvalue), "alert": psi >= threshold}
    return {"method": "PSI plus two-sample Kolmogorov-Smirnov",
            "psi_alert_threshold": threshold,
            "alert": any(row["alert"] for row in results.values()),
            "features": results}
