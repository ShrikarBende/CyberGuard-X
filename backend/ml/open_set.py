"""Shared centroid statistics and calibrated open-set scoring helpers."""
from __future__ import annotations

from typing import Any, Mapping

import numpy as np
from scipy.special import logsumexp


def compute_centroid_statistics(values: np.ndarray, labels: np.ndarray) -> tuple[list[Any], np.ndarray, np.ndarray]:
    """Fit class means and regularized pooled within-class covariance on training data."""
    values = np.asarray(values, dtype=np.float64)
    labels = np.asarray(labels)
    classes = list(np.unique(labels))
    centroids = np.vstack([values[labels == cls].mean(axis=0) for cls in classes])
    residuals = np.concatenate([values[labels == cls] - centroids[i] for i, cls in enumerate(classes)], axis=0)
    covariance = np.atleast_2d(np.cov(residuals, rowvar=False))
    covariance += np.eye(values.shape[1]) * 1e-5
    return classes, centroids, covariance


def nearest_centroid_distance(values: np.ndarray, centroids: np.ndarray, covariance: np.ndarray) -> np.ndarray:
    """Compute normalized (Mahalanobis) distance to the nearest known centroid."""
    values = np.atleast_2d(np.asarray(values, dtype=np.float64))
    centroids = np.asarray(centroids, dtype=np.float64)
    inverse = np.linalg.pinv(np.asarray(covariance, dtype=np.float64))
    distances = []
    for centroid in centroids:
        delta = values - centroid
        distances.append(np.sqrt(np.maximum(np.einsum("ij,jk,ik->i", delta, inverse, delta), 0.0)))
    return np.min(np.vstack(distances), axis=0)


def temperature_scaled_energy(logits: np.ndarray, temperature: float = 1.0) -> np.ndarray:
    """Return higher-is-more-unknown energy using temperature-scaled logits."""
    if temperature <= 0:
        raise ValueError("temperature must be positive")
    values = np.asarray(logits, dtype=np.float64)
    return -float(temperature) * logsumexp(values / float(temperature), axis=1)


def empirical_rank(reference: np.ndarray, values: np.ndarray) -> np.ndarray:
    """Map anomaly scores to [0, 1] using a sorted known-validation reference."""
    sorted_reference = np.sort(np.asarray(reference, dtype=np.float64))
    if not len(sorted_reference):
        raise ValueError("at least one known validation reference score is required")
    return np.searchsorted(sorted_reference, np.asarray(values, dtype=np.float64), side="right") / len(sorted_reference)


def calibrated_union_score(component_references: Mapping[str, np.ndarray],
                           component_values: Mapping[str, np.ndarray]) -> np.ndarray:
    """Calibrate max component anomaly rank to a joint known-validation operating point."""
    if set(component_references) != set(component_values) or not component_references:
        raise ValueError("component reference and value keys must be non-empty and identical")
    ranks = [empirical_rank(component_references[name], component_values[name])
             for name in component_references]
    return np.max(np.vstack(ranks), axis=0)


def calibrated_open_set_score(probabilities: np.ndarray, distance: np.ndarray,
                              distance_bounds: tuple[float, float], anomaly: np.ndarray | None = None,
                              anomaly_bounds: tuple[float, float] | None = None) -> np.ndarray:
    """Higher means more unknown-like; all calibration bounds come from known validation data."""
    probabilities = np.asarray(probabilities, dtype=np.float64)
    confidence_anomaly = 1.0 - probabilities.max(axis=1)
    dlow, dhigh = distance_bounds
    distance_anomaly = np.clip((np.asarray(distance) - dlow) / max(dhigh - dlow, 1e-12), 0, 1)
    signals = [confidence_anomaly, distance_anomaly]
    if anomaly is not None and anomaly_bounds is not None:
        low, high = anomaly_bounds
        signals.append(np.clip((np.asarray(anomaly) - low) / max(high - low, 1e-12), 0, 1))
    return np.mean(np.vstack(signals), axis=0)


def decide_open_set(probabilities: np.ndarray, margins: np.ndarray, distances: np.ndarray,
                    distance_threshold: float, confidence_threshold: float,
                    anomaly: np.ndarray | None = None, anomaly_threshold: float | None = None,
                    margin_threshold: float | None = None) -> np.ndarray:
    """Return row-wise rejection flags from confidence, centroid, and optional anomaly gates."""
    probabilities = np.asarray(probabilities)
    reject = (probabilities.max(axis=1) < confidence_threshold) | (np.asarray(distances) > distance_threshold)
    if margin_threshold is not None:
        reject |= np.asarray(margins) < margin_threshold
    if anomaly is not None and anomaly_threshold is not None:
        reject |= np.asarray(anomaly) > anomaly_threshold
    return reject
