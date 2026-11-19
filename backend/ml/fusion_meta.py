"""Calibrated stacking model for multi-branch incident risk fusion."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np

FEATURE_NAMES = (
    "s_user", "s_endpoint", "s_network_flow", "s_network_graph",
    "s_open_set_distance", "stage_count",
)
FEATURE_GROUPS = {
    "user_contribution": ("s_user",),
    "endpoint_contribution": ("s_endpoint",),
    "network_contribution": ("s_network_flow", "s_network_graph", "stage_count"),
    "open_set_contribution": ("s_open_set_distance",),
}
ARTIFACT_PATH = Path(__file__).resolve().parents[1] / "saved_models" / "risk_fusion_meta.joblib"
_BUNDLE_CACHE: dict | None = None


def normalize_fusion_inputs(values: Mapping[str, Any]) -> np.ndarray:
    """Convert branch output scores and stage count into the six model inputs."""
    vector = []
    for name in FEATURE_NAMES:
        value = float(values.get(name, 0.0) or 0.0)
        if name == "stage_count":
            value = min(max(value, 0.0) / 6.0, 1.0)
        elif name == "s_open_set_distance" and value > 1.0:
            value = value / (1.0 + value)
        else:
            value = min(max(value, 0.0), 1.0)
        vector.append(value)
    return np.asarray(vector, dtype=np.float64).reshape(1, -1)


def severity_tier(probability: float) -> str:
    probability = float(np.clip(probability, 0.0, 1.0))
    if probability < 0.25:
        return "LOW"
    if probability < 0.50:
        return "MEDIUM"
    if probability < 0.75:
        return "HIGH"
    return "CRITICAL"


def load_fusion_bundle(path: Path | str | None = None) -> dict | None:
    global _BUNDLE_CACHE
    target = Path(path) if path else ARTIFACT_PATH
    if path is None and _BUNDLE_CACHE is not None:
        return _BUNDLE_CACHE
    if not target.is_file():
        return None
    bundle = joblib.load(target)
    required = {"scaler", "model", "positive_coefficients", "model_version"}
    missing = required.difference(bundle)
    if missing:
        raise ValueError(f"Risk fusion bundle is missing fields: {sorted(missing)}")
    if path is None:
        _BUNDLE_CACHE = bundle
    return bundle


def _fallback_probability(vector: np.ndarray) -> float:
    """Conservative deterministic fallback until a trained bundle is installed."""
    weights = np.asarray([0.16, 0.17, 0.22, 0.16, 0.17, 0.12])
    evidence = float(np.dot(vector.reshape(-1), weights) / weights.sum())
    return float(np.clip(0.02 + 0.94 * evidence, 0.0, 1.0))


def predict_fused_risk(values: Mapping[str, Any], bundle: Mapping[str, Any] | None = None) -> dict:
    """Return calibrated threat probability, 0-100 risk, tier, and normalized contributions."""
    vector = normalize_fusion_inputs(values)
    active = bundle if bundle is not None else load_fusion_bundle()
    if active:
        scaled = active["scaler"].transform(vector)
        probability = float(active["model"].predict_proba(scaled)[0, 1])
        coefficients = np.asarray(active["positive_coefficients"], dtype=np.float64)
        impacts = np.maximum(scaled[0] * coefficients, 0.0)
        if impacts.sum() <= 1e-12:
            impacts = np.abs(scaled[0] * coefficients)
    else:
        probability = _fallback_probability(vector)
        impacts = vector[0].copy()
    contributions = {}
    for group, names in FEATURE_GROUPS.items():
        contributions[group] = float(sum(impacts[FEATURE_NAMES.index(name)] for name in names))
    total = sum(contributions.values())
    if total <= 1e-12:
        contributions = {name: 25.0 for name in FEATURE_GROUPS}
    else:
        contributions = {name: round(value * 100.0 / total, 2) for name, value in contributions.items()}
        key = next(reversed(contributions))
        contributions[key] = round(contributions[key] + 100.0 - sum(contributions.values()), 2)
    return {
        "probability": float(np.clip(probability, 0.0, 1.0)),
        "score": round(float(np.clip(probability, 0.0, 1.0)) * 100.0, 2),
        "severity": severity_tier(probability),
        "contributions": contributions,
        "inputs": {name: float(vector[0, index]) for index, name in enumerate(FEATURE_NAMES)},
        "model_version": active.get("model_version", "heuristic-fallback") if active else "heuristic-fallback",
        "calibrated": bool(active and active.get("calibrated", False)),
    }
