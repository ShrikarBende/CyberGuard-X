"""Risk score from live classifier probabilities using configured weights.

Attack probability is 1 - P(BENIGN); class probability is the predicted-class
probability for threat candidates and confirmed threats (zero for BENIGN).
The verdict component is 1 for confirmed threats, 0.5 for unconfirmed
candidates, and 0 for BENIGN. Configured weights are normalized before use.
"""
from app.core.config import settings
from ml.fusion_meta import predict_fused_risk


def compute_risk(attack_probability, class_probability, verdict):
    class_probability_value = float(class_probability) if verdict in ("KNOWN_THREAT", "UNKNOWN_CANDIDATE") else 0.0
    verdict_value = {"KNOWN_THREAT": 1.0, "UNKNOWN_CANDIDATE": 0.5, "BENIGN": 0.0}.get(verdict, 0.0)
    components = {
        "attack_probability": {"value": float(attack_probability), "weight": settings.RISK_ANOMALY_WEIGHT},
        "class_probability": {"value": class_probability_value, "weight": settings.RISK_CONFIDENCE_WEIGHT},
        "verdict": {"value": verdict_value, "weight": settings.RISK_VERDICT_WEIGHT},
    }
    total_weight = sum(part["weight"] for part in components.values())
    score = 100 * sum(part["value"] * part["weight"] for part in components.values()) / total_weight
    return {"score": round(score, 2), "breakdown": components}


def compute_correlation_risk(indicator_count: int, layer_count: int, has_model_flag: bool = False):
    """Rule-based correlation score; it is not an ML prediction or probability."""
    indicator_value = min(max(indicator_count, 0) / 7.0, 1.0)
    layer_value = min(max(layer_count, 0) / 3.0, 1.0)
    model_value = 1.0 if has_model_flag else 0.0
    weights = {
        "indicator_coverage": settings.CORRELATION_INDICATOR_WEIGHT,
        "layer_diversity": settings.CORRELATION_LAYER_WEIGHT,
    }
    if has_model_flag:
        # The attached ML score is reported as a component; it does not turn the
        # rule-based correlation score into a classifier prediction.
        weights["model_flag_present"] = 0.0
    total_weight = sum(weights.values()) or 1.0
    components = {
        "indicator_coverage": {"value": round(indicator_value, 4), "weight": weights["indicator_coverage"]},
        "layer_diversity": {"value": round(layer_value, 4), "weight": weights["layer_diversity"]},
        "model_flag_present": {"value": model_value, "weight": weights.get("model_flag_present", 0.0)},
        "indicator_count": indicator_count,
        "layer_count": layer_count,
    }
    score = 100 * (
        indicator_value * weights["indicator_coverage"]
        + layer_value * weights["layer_diversity"]
    ) / total_weight
    return {"score": round(score, 2), "breakdown": components}


def compute_fused_risk(scores: dict):
    """Stack all available branch scores into one calibrated incident risk result."""
    fused = predict_fused_risk(scores)
    return {
        "score": fused["score"],
        "probability": fused["probability"],
        "calibrated_risk_score": fused["calibrated_risk_score"],
        "fusion_confidence": fused["fusion_confidence"],
        "calibration_source": fused["calibration_source"],
        "severity": fused["severity"],
        "contributions": fused["contributions"],
        "inputs": fused["inputs"],
        "model_version": fused["model_version"],
        "calibrated": fused["calibrated"],
        "breakdown": {"fusion": fused},
    }
