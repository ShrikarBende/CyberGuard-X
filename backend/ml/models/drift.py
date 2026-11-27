"""Feature and prediction drift monitoring using PSI and two-sample KS tests."""
from __future__ import annotations

from typing import Any, Sequence

import numpy as np
from scipy.stats import ks_2samp

from app.core.config import settings


def compute_psi(
    reference: Sequence[float] | np.ndarray,
    current: Sequence[float] | np.ndarray,
    *,
    bins: int = 10,
    eps: float = 1e-6,
) -> float:
    """Compute Population Stability Index (PSI) between reference and current 1D arrays."""
    ref = np.asarray(reference, dtype=np.float64)
    cur = np.asarray(current, dtype=np.float64)
    ref = ref[np.isfinite(ref)]
    cur = cur[np.isfinite(cur)]
    if ref.size == 0 or cur.size == 0:
        return 0.0

    quantiles = np.linspace(0.0, 1.0, max(2, int(bins)) + 1)
    edges = np.unique(np.quantile(ref, quantiles))
    if edges.size < 2:
        # Constant reference feature: check if current stays at the same constant
        return 0.0 if np.allclose(cur, ref[0]) else 1.0

    edges[0] = -np.inf
    edges[-1] = np.inf
    ref_counts, _ = np.histogram(ref, bins=edges)
    cur_counts, _ = np.histogram(cur, bins=edges)

    ref_pct = np.clip(ref_counts / max(ref.size, 1), eps, 1.0)
    cur_pct = np.clip(cur_counts / max(cur.size, 1), eps, 1.0)
    psi = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
    return float(max(0.0, psi))


def compute_ks(
    reference: Sequence[float] | np.ndarray,
    current: Sequence[float] | np.ndarray,
) -> tuple[float, float]:
    """Compute two-sample Kolmogorov-Smirnov statistic and p-value."""
    ref = np.asarray(reference, dtype=np.float64)
    cur = np.asarray(current, dtype=np.float64)
    ref = ref[np.isfinite(ref)]
    cur = cur[np.isfinite(cur)]
    if ref.size == 0 or cur.size == 0:
        return 0.0, 1.0
    stat, pvalue = ks_2samp(ref, cur)
    return float(stat), float(pvalue)


def evaluate_drift(
    reference_features: np.ndarray,
    current_features: np.ndarray,
    *,
    feature_names: Sequence[str] | None = None,
    reference_predictions: Sequence[float] | np.ndarray | None = None,
    current_predictions: Sequence[float] | np.ndarray | None = None,
    psi_threshold: float | None = None,
    ks_threshold: float | None = None,
    prediction_psi_threshold: float | None = None,
    bins: int = 10,
) -> dict[str, Any]:
    """Evaluate feature-level PSI/KS drift and prediction-distribution shift."""
    ref_x = np.asarray(reference_features, dtype=np.float64)
    cur_x = np.asarray(current_features, dtype=np.float64)
    if ref_x.ndim == 1:
        ref_x = ref_x.reshape(-1, 1)
    if cur_x.ndim == 1:
        cur_x = cur_x.reshape(-1, 1)
    if ref_x.shape[1] != cur_x.shape[1]:
        raise ValueError(
            f"Feature count mismatch: reference has {ref_x.shape[1]}, current has {cur_x.shape[1]}"
        )

    psi_lim = float(settings.DRIFT_PSI_THRESHOLD if psi_threshold is None else psi_threshold)
    ks_lim = float(settings.DRIFT_KS_THRESHOLD if ks_threshold is None else ks_threshold)
    pred_lim = float(
        settings.DRIFT_PREDICTION_PSI_THRESHOLD
        if prediction_psi_threshold is None
        else prediction_psi_threshold
    )

    names = list(feature_names) if feature_names is not None else [
        f"feature_{i}" for i in range(ref_x.shape[1])
    ]
    if len(names) != ref_x.shape[1]:
        raise ValueError("feature_names length must match number of feature columns")

    per_feature: dict[str, dict[str, Any]] = {}
    drifted_features: list[str] = []
    max_psi = 0.0
    max_ks = 0.0
    for idx, name in enumerate(names):
        psi = compute_psi(ref_x[:, idx], cur_x[:, idx], bins=bins)
        ks_stat, ks_p = compute_ks(ref_x[:, idx], cur_x[:, idx])
        drifted = bool(psi >= psi_lim or ks_stat >= ks_lim)
        if drifted:
            drifted_features.append(name)
        max_psi = max(max_psi, psi)
        max_ks = max(max_ks, ks_stat)
        per_feature[name] = {
            "psi": round(psi, 6),
            "ks_statistic": round(ks_stat, 6),
            "ks_pvalue": round(ks_p, 6),
            "drifted": drifted,
        }

    prediction_shift: dict[str, Any] | None = None
    pred_drifted = False
    if reference_predictions is not None and current_predictions is not None:
        pred_psi = compute_psi(reference_predictions, current_predictions, bins=bins)
        pred_ks, pred_p = compute_ks(reference_predictions, current_predictions)
        pred_drifted = bool(pred_psi >= pred_lim or pred_ks >= ks_lim)
        prediction_shift = {
            "psi": round(pred_psi, 6),
            "ks_statistic": round(pred_ks, 6),
            "ks_pvalue": round(pred_p, 6),
            "drifted": pred_drifted,
        }

    return {
        "drift_detected": bool(drifted_features or pred_drifted),
        "thresholds": {
            "psi": psi_lim,
            "ks": ks_lim,
            "prediction_psi": pred_lim,
        },
        "summary": {
            "reference_rows": int(ref_x.shape[0]),
            "current_rows": int(cur_x.shape[0]),
            "features_checked": len(names),
            "drifted_feature_count": len(drifted_features),
            "drifted_features": drifted_features,
            "max_psi": round(max_psi, 6),
            "max_ks": round(max_ks, 6),
            "prediction_drifted": pred_drifted,
        },
        "features": per_feature,
        "prediction_shift": prediction_shift,
    }
