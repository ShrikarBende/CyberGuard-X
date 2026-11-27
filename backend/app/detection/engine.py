"""CICIDS2017 LightGBM inference for supported network flow events."""
from __future__ import annotations

import logging
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import joblib
import numpy as np
import pandas as pd
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.detection.risk import compute_fused_risk
from app.correlation.indicators import evaluate_indicators
from app.models.entities import (
    DetectionResult,
    Incident,
    IncidentEvent,
    MitreTechnique,
    RiskScore,
    SecurityEvent,
)
from app.schemas.schemas import SecurityEventCreate
from app.services.websocket_manager import ws_manager
from ml.preprocessing.cicids_pipeline import (
    HostWindowAggregator,
    add_protocol_invariant_features,
    add_service_port_buckets,
    apply_log1p_columns,
)
from ml.open_set import (calibrated_open_set_score, calibrated_union_score, decide_open_set,
                         nearest_centroid_distance, temperature_scaled_energy)
from ml.endpoint_branch import extract_endpoint_features, predict_endpoint
from ml.sequence_graph import predict_graph_edge, predict_user_sequence, sequence_for_event

logger = logging.getLogger(__name__)
MODEL_BUNDLE_PATH = Path(settings.MODEL_BUNDLE_PATH)
_MODEL_BUNDLE_CACHE: Optional[Dict[str, Any]] = None
_BACKEND_DIR = Path(__file__).resolve().parents[2]
_SAVED_MODELS_DIR = Path(settings.SAVED_MODELS_DIR).expanduser()
if not _SAVED_MODELS_DIR.is_absolute():
    _SAVED_MODELS_DIR = (_BACKEND_DIR / _SAVED_MODELS_DIR).resolve()
ENDPOINT_BUNDLE_PATH = _SAVED_MODELS_DIR / "endpoint_behavior.bundle.pkl"
_ENDPOINT_BUNDLE_CACHE: Optional[Dict[str, Any]] = None
USER_BUNDLE_PATH = _SAVED_MODELS_DIR / "user_tft.bundle.pkl"
NETWORK_GAT_BUNDLE_PATH = _SAVED_MODELS_DIR / "network_gat.bundle.pkl"
_USER_BUNDLE_CACHE: Optional[Dict[str, Any]] = None
_NETWORK_GAT_BUNDLE_CACHE: Optional[Dict[str, Any]] = None
_LIVE_HOST_WINDOWS = HostWindowAggregator(max_events_per_source=2048, max_sources=4096)
_VERIFIED_NOVEL_BUFFER: list[np.ndarray] = []


def adapt_from_analyst_feedback(event_features: np.ndarray, analyst_verdict: str) -> dict[str, Any]:
    """Keep analyst-confirmed novel embeddings as an opt-in runtime reference cluster.

    This does not alter the trained bundles or existing decision thresholds. Matching
    subsequent embeddings can query ``verified_novel_distance`` for analyst review.
    """
    vector = np.asarray(event_features, dtype=np.float64).reshape(-1)
    if analyst_verdict != "CONFIRMED_NOVEL" or not vector.size or not np.isfinite(vector).all():
        return {"accepted": False, "buffer_size": len(_VERIFIED_NOVEL_BUFFER)}
    _VERIFIED_NOVEL_BUFFER.append(vector.copy())
    return {"accepted": True, "buffer_size": len(_VERIFIED_NOVEL_BUFFER)}


def verified_novel_distance(event_features: np.ndarray) -> float | None:
    """Euclidean distance to the centroid of compatible verified novel samples."""
    vector = np.asarray(event_features, dtype=np.float64).reshape(-1)
    compatible = [row for row in _VERIFIED_NOVEL_BUFFER if row.shape == vector.shape]
    if not compatible:
        return None
    centroid = np.mean(compatible, axis=0)
    return float(np.linalg.norm(vector - centroid))


def _should_suppress_borderline_flow_alert(event: SecurityEvent, prediction: dict,
                                          risk_result: dict, db: Session,
                                          host_context: dict | None = None) -> bool:
    """Avoid standalone incidents for uncorroborated borderline network predictions."""
    if prediction.get("verdict") == "UNKNOWN_NOVEL" or prediction.get("decision_outcome") == "UNKNOWN_NOVEL":
        return False
    if prediction.get("verdict") != "KNOWN_THREAT":
        return False
    inputs = risk_result.get("inputs", {})
    confidence = float(inputs.get("s_network_flow") or prediction.get("attack_probability") or
                       prediction.get("probability") or 0.0)
    if not 0.50 <= confidence < 0.85:
        return False
    context = host_context or {}
    if (float(context.get("win_unique_dst_ports_60s", 0.0) or 0.0) >= 10 or
            float(context.get("suspicious_flows_60s", 0.0) or 0.0) >= 5):
        return False
    if (float(inputs.get("s_endpoint", 0.0) or 0.0) >= 0.95 or
            float(inputs.get("s_user", 0.0) or 0.0) >= 0.5 or
            float(inputs.get("s_network_graph", 0.0) or 0.0) >= 0.5):
        return False
    cutoff = event.timestamp - timedelta(minutes=60)
    match = [SecurityEvent.timestamp >= cutoff]
    entities = []
    if event.user_id:
        entities.append(SecurityEvent.user_id == event.user_id)
    if event.device_id:
        entities.append(SecurityEvent.device_id == event.device_id)
    if event.source_ip:
        entities.append(SecurityEvent.source_ip == event.source_ip)
    if not entities:
        return False
    rows = (db.query(SecurityEvent).filter(*match, or_(*entities))
            .order_by(SecurityEvent.timestamp.asc()).all())
    suspicious_flows = 0
    for row in rows:
        if not event.source_ip or row.source_ip != event.source_ip:
            continue
        detection = row.detection_result
        if detection and detection.verdict in {"KNOWN_THREAT", "UNKNOWN_NOVEL"}:
            if float(detection.attack_probability or detection.probability or 0.0) >= 0.50:
                suspicious_flows += 1
    if suspicious_flows >= 5:
        return False
    related_ids = {row.event_id for row in rows}
    if any(item["name"] != "model_flagged_flow" and related_ids.intersection(item.get("event_ids", []))
           for item in evaluate_indicators(rows)):
        return False
    for row in rows:
        detection = row.detection_result
        if detection is None:
            continue
        details = detection.details or {}
        user_data = details.get("user_sequence") or {}
        graph_data = details.get("network_graph") or {}
        if (float(details.get("s_endpoint", 0.0) or 0.0) >= 0.95 or
            float(details.get("s_network_graph", graph_data.get("s_network_graph", 0.0)) or 0.0) >= 0.5 or float(
            details.get("s_user", user_data.get("s_user", 0.0)) or 0.0
        ) >= 0.5):
            return False
    return True


def _update_live_host_context(event: SecurityEvent, flow_row: dict | None = None) -> dict[str, float]:
    payload = event.raw_payload if isinstance(event.raw_payload, dict) else {}
    payload_features = payload.get("cicids_features", {}) if isinstance(payload.get("cicids_features"), dict) else {}
    extra_features = {**payload_features, **(flow_row or {})}
    row = {**payload, **extra_features,
           "source_ip": event.source_ip, "destination_ip": event.destination_ip,
           "destination_port": event.destination_port, "timestamp": event.timestamp,
           "bytes_transferred": event.bytes_transferred if event.bytes_transferred else None}
    return _LIVE_HOST_WINDOWS.update(row)


def load_endpoint_bundle() -> Optional[Dict[str, Any]]:
    """Load endpoint behavioral model bundle when it has been trained."""
    global _ENDPOINT_BUNDLE_CACHE
    if _ENDPOINT_BUNDLE_CACHE is None and ENDPOINT_BUNDLE_PATH.is_file():
        bundle = joblib.load(ENDPOINT_BUNDLE_PATH)
        required = {"dae", "isolation_forest", "feature_names", "feature_min", "feature_range",
                    "reconstruction_bounds", "iforest_bounds", "model_version"}
        missing = required.difference(bundle)
        if missing:
            raise ValueError(f"Endpoint model bundle is missing fields: {sorted(missing)}")
        _ENDPOINT_BUNDLE_CACHE = bundle
    return _ENDPOINT_BUNDLE_CACHE


def load_user_bundle() -> Optional[Dict[str, Any]]:
    """Load the optional user-sequence TFT bundle once per process."""
    global _USER_BUNDLE_CACHE
    if _USER_BUNDLE_CACHE is None and USER_BUNDLE_PATH.is_file():
        bundle = joblib.load(USER_BUNDLE_PATH)
        required = {"model", "feature_names", "feature_min", "feature_range", "sequence_length", "model_version"}
        missing = required.difference(bundle)
        if missing:
            raise ValueError(f"User TFT bundle is missing fields: {sorted(missing)}")
        _USER_BUNDLE_CACHE = bundle
    return _USER_BUNDLE_CACHE


def load_network_gat_bundle() -> Optional[Dict[str, Any]]:
    """Load the optional communication-graph GAT bundle once per process."""
    global _NETWORK_GAT_BUNDLE_CACHE
    if _NETWORK_GAT_BUNDLE_CACHE is None and NETWORK_GAT_BUNDLE_PATH.is_file():
        bundle = joblib.load(NETWORK_GAT_BUNDLE_PATH)
        required = {"model", "host_index", "node_features_by_host", "incoming_by_host", "model_version"}
        missing = required.difference(bundle)
        if missing:
            raise ValueError(f"Network GAT bundle is missing fields: {sorted(missing)}")
        _NETWORK_GAT_BUNDLE_CACHE = bundle
    return _NETWORK_GAT_BUNDLE_CACHE


def _predict_user_event(event: SecurityEvent, bundle: Dict[str, Any], db: Session) -> Dict[str, Any]:
    """Score this event with the user's latest persisted event history."""
    query = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == event.user_id,
        SecurityEvent.event_id != event.event_id,
    ).order_by(SecurityEvent.timestamp.desc())
    history = list(reversed(query.limit(max(0, int(bundle["sequence_length"]) - 1)).all()))
    sequence = sequence_for_event(event, bundle["sequence_length"], history=history)
    return predict_user_sequence(sequence, bundle)


def _upsert_grouped_flow_incident(event: SecurityEvent, prediction: Dict[str, Any], bundle: Dict[str, Any],
                                 risk_result: Dict[str, Any], attack_probability: float,
                                 db: Session) -> str:
    """Create or update a deterministic class/source/time-window incident."""
    verdict = prediction["verdict"]
    predicted_class = prediction["predicted_class"]
    source_ip = event.source_ip or "unknown"
    window_minutes = max(1, int(settings.INCIDENT_WINDOW_MINUTES))
    event_time = event.timestamp
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    else:
        event_time = event_time.astimezone(timezone.utc)
    window_bucket = int(event_time.timestamp() // (window_minutes * 60))
    group_material = f"{verdict}|{predicted_class}|{source_ip}|{window_minutes}|{window_bucket}"
    group_key = hashlib.sha256(group_material.encode("utf-8")).hexdigest()
    incident = db.query(Incident).filter(Incident.group_key == group_key).first()
    is_new = incident is None
    risk_score = float(risk_result["score"])
    severity = risk_result.get("severity", "MEDIUM")
    score_value = float(prediction["score"])
    if is_new:
        unknown = verdict in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"}
        incident = Incident(
            incident_id=f"inc_{uuid.uuid4().hex[:12]}",
            group_key=group_key,
            title=(f"CICIDS2017 {predicted_class} review" if unknown else f"CICIDS2017 {predicted_class} detection"),
            description=("Low model margin; not a confirmed novel attack." if unknown else
                         f"LightGBM {bundle['model_version']} classified network flows as {predicted_class}."),
            severity=severity,
            status="NEEDS_REVIEW" if unknown else "OPEN",
            threat_classification=verdict,
            overall_risk_score=risk_score,
            user_id=event.user_id,
            device_id=event.device_id,
            attack_sequence=None,
            evidence={
                "source_ip": source_ip,
                "predicted_class": predicted_class,
                "window_minutes": window_minutes,
                "window_bucket": window_bucket,
                "review_text": "Low model margin; not a confirmed novel attack." if unknown else None,
                "risk_breakdown": risk_result["breakdown"],
                "risk_fusion": {key: risk_result[key] for key in ("probability", "severity", "contributions", "inputs", "model_version", "calibrated")},
                "score_summary": {"count": 1, "min": score_value, "max": score_value, "mean": score_value},
                "sample_event_count": 0,
            },
            flow_count=1,
            first_detected_at=event_time,
            last_updated_at=event_time,
        )
        db.add(incident)
        db.flush()
        db.add(RiskScore(
            incident_id=incident.incident_id,
            score=risk_score,
            category=severity,
            anomaly_factor=attack_probability,
            user_risk_component=risk_result["contributions"]["user_contribution"],
            endpoint_risk_component=risk_result["contributions"]["endpoint_contribution"],
            network_risk_component=risk_result["contributions"]["network_contribution"],
            top_contributing_features=None,
            explanation_summary=None,
            risk_breakdown=risk_result["breakdown"],
        ))
    else:
        evidence = dict(incident.evidence or {})
        summary = dict(evidence.get("score_summary") or {"count": 0, "min": score_value, "max": score_value, "mean": 0.0})
        old_count = int(summary.get("count", 0))
        new_count = old_count + 1
        summary["min"] = min(float(summary.get("min", score_value)), score_value)
        summary["max"] = max(float(summary.get("max", score_value)), score_value)
        summary["mean"] = (float(summary.get("mean", 0.0)) * old_count + score_value) / new_count
        summary["count"] = new_count
        evidence["score_summary"] = summary
        incident.evidence = evidence
        incident.flow_count = int(incident.flow_count or 0) + 1
        if risk_score >= float(incident.overall_risk_score):
            incident.overall_risk_score = risk_score
            incident.severity = severity
            evidence["risk_breakdown"] = risk_result["breakdown"]
            evidence["risk_fusion"] = {key: risk_result[key] for key in ("probability", "severity", "contributions", "inputs", "model_version", "calibrated")}
            incident.evidence = evidence
        first_time = incident.first_detected_at
        if first_time.tzinfo is None:
            first_time = first_time.replace(tzinfo=timezone.utc)
        if event_time < first_time:
            incident.first_detected_at = event_time
        last_time = incident.last_updated_at
        if last_time.tzinfo is None:
            last_time = last_time.replace(tzinfo=timezone.utc)
        if event_time > last_time:
            incident.last_updated_at = event_time
        risk_detail = db.query(RiskScore).filter(RiskScore.incident_id == incident.incident_id).first()
        if risk_detail:
            previous_score = float(risk_detail.score)
            risk_detail.score = max(float(risk_detail.score), risk_score)
            risk_detail.category = incident.severity
            risk_detail.anomaly_factor = max(float(risk_detail.anomaly_factor or 0.0), attack_probability)
            if risk_score >= previous_score:
                risk_detail.risk_breakdown = risk_result["breakdown"]
                risk_detail.user_risk_component = risk_result["contributions"]["user_contribution"]
                risk_detail.endpoint_risk_component = risk_result["contributions"]["endpoint_contribution"]
                risk_detail.network_risk_component = risk_result["contributions"]["network_contribution"]

    sample_count = db.query(func.count(IncidentEvent.id)).filter(
        IncidentEvent.incident_id == incident.incident_id
    ).scalar() or 0
    if sample_count < 200:
        db.add(IncidentEvent(
            incident_id=incident.incident_id,
            event_id=event.event_id,
            stage="classification",
            order=sample_count,
        ))
        evidence = dict(incident.evidence or {})
        evidence["sample_event_count"] = sample_count + 1
        incident.evidence = evidence

    mitre_mapping = {
        "BruteForce": ("Credential Access", "T1110"),
        "PortScan": ("Discovery", "T1046"),
        "DosDDoS": ("Impact", "T1498"),
    }.get(predicted_class)
    if verdict == "KNOWN_THREAT" and mitre_mapping and prediction["probability"] >= settings.MITRE_MIN_PROBABILITY:
        existing_mapping = db.query(MitreTechnique).filter(
            MitreTechnique.incident_id == incident.incident_id,
            MitreTechnique.technique_id == mitre_mapping[1],
        ).first()
        if not existing_mapping:
            db.add(MitreTechnique(
                incident_id=incident.incident_id,
                tactic=mitre_mapping[0],
                technique_id=mitre_mapping[1],
                technique_name=predicted_class,
                confidence=prediction["probability"],
                is_verified=False,
            ))
    db.flush()
    return incident.incident_id


def load_model_bundle() -> Optional[Dict[str, Any]]:
    """Load the configured real-data model bundle once per process."""
    global _MODEL_BUNDLE_CACHE
    if _MODEL_BUNDLE_CACHE is None:
        if not MODEL_BUNDLE_PATH.is_file():
            raise FileNotFoundError(
                f"Configured CICIDS model bundle was not found: {MODEL_BUNDLE_PATH}. "
                "Set MODEL_BUNDLE_PATH to an existing bundle; no alternate bundle is loaded."
            )
        bundle = joblib.load(MODEL_BUNDLE_PATH)
        required = {
            "model", "scaler", "feature_names", "log1p_columns", "class_names",
            "tau", "score_name", "model_version", "data_hash", "seed", "training_date",
            "evaluation_json_path", "profile",
        }
        missing = required.difference(bundle)
        if missing:
            raise ValueError(f"Model bundle is missing fields: {sorted(missing)}")
        _MODEL_BUNDLE_CACHE = bundle
    return _MODEL_BUNDLE_CACHE


def _event_payload(event_in: SecurityEventCreate, event_id: str, verdict: str, **extra):
    return {
        "type": "SECURITY_EVENT",
        "event_id": event_id,
        "timestamp": event_in.timestamp.isoformat(),
        "user_id": event_in.user_id,
        "device_id": event_in.device_id,
        "category": event_in.event_category,
        "event_type": event_in.event_type,
        "dataset": event_in.dataset,
        "verdict": verdict,
        "incident_id": None,
        "risk_score": None,
        "risk_breakdown": None,
        "mitre_mappings": [],
        **extra,
    }


def predict_flow(flow: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Score a CICIDS flow without persistence or side effects."""
    names = bundle["feature_names"]
    missing = [name for name in names if name not in flow]
    if missing:
        raise ValueError(f"CICIDS2017 flow features missing: {', '.join(missing[:5])}")
    raw = np.asarray([[flow[name] for name in names]], dtype=np.float32)
    if not np.isfinite(raw).all():
        raise ValueError("CICIDS2017 flow features must be finite")
    transformed = apply_log1p_columns(raw, np.asarray(bundle["log1p_columns"], dtype=bool))
    scaled = bundle["scaler"].transform(transformed)
    raw_scores = np.asarray(bundle["model"].predict(scaled, raw_score=True)[0], dtype=float)
    probabilities = np.asarray(bundle["model"].predict_proba(scaled)[0], dtype=float)
    names = list(bundle["class_names"])
    if "BENIGN" not in names:
        raise ValueError("Configured CICIDS model bundle must include the BENIGN class to compute attack_probability.")
    if raw_scores.size != len(names) or probabilities.size != len(names):
        raise ValueError("Model output columns do not match bundle class_names.")
    index = int(np.argmax(raw_scores))
    predicted_class = names[index]
    score = float(np.max(raw_scores) - np.partition(raw_scores, -2)[-2])
    probability = float(probabilities[index])
    tau = float(bundle["tau"])
    open_set_details = {}
    if "class_centroids" in bundle and "centroid_covariance" in bundle:
        centroid_input = scaled
        if bundle.get("compact_pca") is not None:
            centroid_input = bundle["compact_pca"].transform(bundle["compact_scaler"].transform(scaled))
        distance = float(nearest_centroid_distance(centroid_input, bundle["class_centroids"], bundle["centroid_covariance"])[0])
        anomaly = None
        anomaly_score = None
        if bundle.get("open_set_isolation_forest") is not None:
            anomaly_score = float(-bundle["open_set_isolation_forest"].score_samples(scaled)[0])
            anomaly = np.asarray([anomaly_score])
        raw_component_values = {
            "confidence": np.asarray([1.0 - float(probabilities.max())]),
            "compact_mahalanobis": np.asarray([distance]),
        }
        ordered_logits = np.sort(raw_scores)
        raw_component_values["logit_margin"] = np.asarray([-(ordered_logits[-1] - ordered_logits[-2])])
        energy = None
        if bundle.get("energy_temperature") is not None:
            energy = float(temperature_scaled_energy(raw_scores.reshape(1, -1), bundle["energy_temperature"])[0])
            raw_component_values["energy"] = np.asarray([energy])
        if anomaly_score is not None:
            raw_component_values["isolation_forest"] = anomaly
        if bundle.get("open_set_component_references"):
            references = {name: bundle["open_set_component_references"][name]
                          for name in raw_component_values if name in bundle["open_set_component_references"]}
            values = {name: raw_component_values[name] for name in references}
            open_set_score = float(calibrated_union_score(references, values)[0])
            rejected = open_set_score > float(bundle["open_set_union_threshold"])
        else:
            rejected = bool(decide_open_set(
                probabilities.reshape(1, -1), np.asarray([score]), np.asarray([distance]),
                float(bundle["centroid_distance_threshold"]), float(bundle["confidence_threshold"]),
                anomaly, bundle.get("anomaly_score_threshold"), tau,
            )[0])
            open_set_score = float(calibrated_open_set_score(
                probabilities.reshape(1, -1), np.asarray([distance]), bundle["centroid_distance_bounds"],
                anomaly, bundle.get("anomaly_score_bounds"),
            )[0])
        low_confidence = probability < float(bundle.get("confidence_threshold", 0.0))
        low_margin = score < float(bundle.get("margin_threshold", tau))
        energy_far = (energy is not None and bundle.get("energy_anomaly_threshold") is not None
                      and energy > float(bundle["energy_anomaly_threshold"]))
        distance_far = distance > float(bundle["centroid_distance_threshold"])
        anomaly_far = (anomaly_score is not None and bundle.get("anomaly_score_threshold") is not None
                       and anomaly_score > float(bundle["anomaly_score_threshold"]))
        # Older bundles have no separate energy gate. Preserve their trained
        # reject threshold while newly calibrated bundles require joint signals.
        has_energy_gate = bundle.get("energy_anomaly_threshold") is not None
        novel = bool(rejected and (distance_far or anomaly_far) and
                     ((low_confidence or energy_far or low_margin) if has_energy_gate else (low_confidence or distance_far or anomaly_far)))
        ambiguous = bool(not novel and (low_confidence or low_margin))
        decision = "UNKNOWN_NOVEL" if novel else ("ABSTAIN_NEEDS_REVIEW" if ambiguous else predicted_class)
        open_set_details = {"open_set_label": decision,
                            "centroid_distance": distance, "open_set_score": open_set_score,
                            "branch_anomaly_score": anomaly_score, "energy_anomaly_score": energy,
                            "decision_outcome": decision}
        verdict = ("UNKNOWN_CANDIDATE" if decision == "ABSTAIN_NEEDS_REVIEW" else decision) if decision in {"UNKNOWN_NOVEL", "ABSTAIN_NEEDS_REVIEW"} else (
            "BENIGN" if predicted_class == "BENIGN" else "KNOWN_THREAT"
        )
    else:
        verdict = "UNKNOWN_CANDIDATE" if score < tau else (
            "BENIGN" if predicted_class == "BENIGN" else "KNOWN_THREAT"
        )
    if verdict == "UNKNOWN_CANDIDATE":
        open_set_details["decision_outcome"] = "ABSTAIN_NEEDS_REVIEW"
    return {
        "class_names": names, "probabilities": probabilities,
        "probability_by_class": {name: float(probabilities[i]) for i, name in enumerate(names)},
        "predicted_class": predicted_class, "score": score, "probability": probability,
        "tau": tau, "verdict": verdict,
        **open_set_details,
    }


def score_batch(frame, bundle: Dict[str, Any], events: list[SecurityEvent] | None = None) -> list[Dict[str, Any]]:
    """Score CICIDS flows together while preserving ``predict_flow`` semantics."""
    feature_names = list(bundle["feature_names"])
    class_names = list(bundle["class_names"])
    if "BENIGN" not in class_names:
        raise ValueError("Configured CICIDS model bundle must include the BENIGN class.")
    frame = frame.copy()
    add_protocol_invariant_features(frame)
    fallback_ports = ([event.destination_port for event in events]
                      if events is not None and len(events) == len(frame) else None)
    add_service_port_buckets(frame, fallback_ports)
    host_contexts: list[dict[str, float]] = [{} for _ in range(len(frame))]
    if events is not None and len(events) == len(frame):
        for index in sorted(range(len(events)), key=lambda i: events[i].timestamp):
            host_contexts[index] = _update_live_host_context(events[index], frame.iloc[index].to_dict())
        for name in set(feature_names).intersection(host_contexts[0] if host_contexts else {}):
            frame[name] = [context.get(name, 0.0) for context in host_contexts]
    missing = [name for name in feature_names if name not in frame.columns]
    if missing:
        raise ValueError(f"CICIDS2017 flow features missing: {', '.join(missing[:5])}")
    raw = np.asarray(frame[feature_names], dtype=np.float32)
    if raw.ndim != 2 or raw.shape[1] != len(feature_names):
        raise ValueError("CICIDS2017 batch has an invalid feature shape.")
    if not np.isfinite(raw).all():
        raise ValueError("CICIDS2017 flow features must be finite")
    transformed = apply_log1p_columns(raw, np.asarray(bundle["log1p_columns"], dtype=bool))
    scaled = bundle["scaler"].transform(transformed)
    raw_scores = np.asarray(bundle["model"].predict(scaled, raw_score=True), dtype=float)
    probabilities = np.asarray(bundle["model"].predict_proba(scaled), dtype=float)
    expected_shape = (len(frame), len(class_names))
    if raw_scores.shape != expected_shape or probabilities.shape != expected_shape:
        raise ValueError("Model output columns do not match batch rows and bundle class_names.")
    best_indexes = np.argmax(raw_scores, axis=1)
    sorted_scores = np.sort(raw_scores, axis=1)
    margins = sorted_scores[:, -1] - sorted_scores[:, -2]
    tau = float(bundle["tau"])
    results = []
    for row_index, best_index in enumerate(best_indexes):
        predicted_class = class_names[int(best_index)]
        row_probabilities = probabilities[row_index]
        probability = float(probabilities[row_index, best_index])
        score = float(margins[row_index])
        verdict = "UNKNOWN_CANDIDATE" if score < tau else (
            "BENIGN" if predicted_class == "BENIGN" else "KNOWN_THREAT"
        )
        open_set_details = {}
        if "class_centroids" in bundle and "centroid_covariance" in bundle:
            one_scaled = scaled[row_index:row_index + 1]
            centroid_input = one_scaled
            if bundle.get("compact_pca") is not None:
                centroid_input = bundle["compact_pca"].transform(bundle["compact_scaler"].transform(one_scaled))
            distance = float(nearest_centroid_distance(centroid_input, bundle["class_centroids"], bundle["centroid_covariance"])[0])
            anomaly = None
            anomaly_value = None
            if bundle.get("open_set_isolation_forest") is not None:
                anomaly_value = float(-bundle["open_set_isolation_forest"].score_samples(one_scaled)[0])
                anomaly = np.asarray([anomaly_value])
            raw_component_values = {
                "confidence": np.asarray([1.0 - float(row_probabilities.max())]),
                "compact_mahalanobis": np.asarray([distance]),
            }
            ordered_logits = np.sort(raw_scores[row_index])
            raw_component_values["logit_margin"] = np.asarray([-(ordered_logits[-1] - ordered_logits[-2])])
            energy_value = None
            if bundle.get("energy_temperature") is not None:
                energy_value = float(temperature_scaled_energy(raw_scores[row_index:row_index + 1], bundle["energy_temperature"])[0])
                raw_component_values["energy"] = np.asarray([energy_value])
            if anomaly_value is not None:
                raw_component_values["isolation_forest"] = anomaly
            if bundle.get("open_set_component_references"):
                references = {name: bundle["open_set_component_references"][name]
                              for name in raw_component_values if name in bundle["open_set_component_references"]}
                values = {name: raw_component_values[name] for name in references}
                open_set_score = float(calibrated_union_score(references, values)[0])
                rejected = open_set_score > float(bundle["open_set_union_threshold"])
            else:
                rejected = bool(decide_open_set(
                    row_probabilities.reshape(1, -1), np.asarray([score]), np.asarray([distance]),
                    float(bundle["centroid_distance_threshold"]), float(bundle["confidence_threshold"]),
                    anomaly, bundle.get("anomaly_score_threshold"), tau,
                )[0])
                open_set_score = float(calibrated_open_set_score(
                    row_probabilities.reshape(1, -1), np.asarray([distance]),
                    bundle["centroid_distance_bounds"], anomaly, bundle.get("anomaly_score_bounds"))[0])
            verdict = "UNKNOWN_NOVEL" if rejected else ("BENIGN" if predicted_class == "BENIGN" else "KNOWN_THREAT")
            open_set_details = {"open_set_label": "UNKNOWN_NOVEL" if rejected else predicted_class,
                                "centroid_distance": distance,
                                "open_set_score": open_set_score,
                                "branch_anomaly_score": anomaly_value,
                                "energy_anomaly_score": energy_value}
        results.append({
            "host_window": host_contexts[row_index],
            "class_names": class_names,
            "probabilities": row_probabilities,
            "probability_by_class": {
                name: float(row_probabilities[index]) for index, name in enumerate(class_names)
            },
            "predicted_class": predicted_class,
            "score": score,
            "probability": probability,
            "tau": tau,
            "verdict": verdict,
            **open_set_details,
        })
    return results


def persist_scored_batch(events: list[SecurityEvent], predictions: list[Dict[str, Any]], bundle: Dict[str, Any], db: Session) -> Dict[str, int]:
    """Persist detections in a batch and group threat/review incidents."""
    if len(events) != len(predictions):
        raise ValueError("Batch events and predictions must have the same number of rows.")
    detection_rows = []
    counts: Dict[str, int] = {}
    grouped_incident_ids = {}
    host_context_by_event = {}
    for event, prediction in zip(events, predictions):
        host_context_by_event[event.event_id] = prediction.get("host_window") or _update_live_host_context(event)
    for event, prediction in zip(events, predictions):
        verdict = prediction["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        class_names = prediction["class_names"]
        probabilities = prediction["probabilities"]
        score = float(prediction["score"])
        probability = float(prediction["probability"])
        attack_probability = float(1.0 - probabilities[class_names.index("BENIGN")])
        fusion_inputs = {
            "s_network_flow": attack_probability,
            "s_open_set_distance": prediction.get("open_set_score", prediction.get("centroid_distance", 0.0)),
            "stage_count": 1,
        }
        risk_result = compute_fused_risk(fusion_inputs)
        detection_id = f"det_{uuid.uuid4().hex[:12]}"
        flow = (event.raw_payload or {}).get("cicids_features", {})
        detection_rows.append(DetectionResult(
            detection_id=detection_id,
            event_id=event.event_id,
            verdict=verdict,
            predicted_class=prediction["predicted_class"],
            probability=probability,
            score=score,
            attack_probability=attack_probability,
            open_set_distance=None,
            reconstruction_error=None,
            layer="network",
            details={
                "cicids_features": {name: float(flow[name]) for name in bundle["feature_names"]},
                "class_probabilities": prediction["probability_by_class"],
                "score_name": bundle["score_name"],
                "score": score,
                "risk_breakdown": risk_result["breakdown"],
                "risk_fusion": {key: risk_result[key] for key in ("probability", "severity", "contributions", "inputs", "model_version", "calibrated")},
                "s_network_flow": attack_probability,
                "host_window": host_context_by_event.get(event.event_id, {}),
                "open_set_score": prediction.get("open_set_score"),
                "centroid_distance": prediction.get("centroid_distance"),
                "open_set_label": prediction.get("open_set_label"),
            },
            model_version=bundle["model_version"],
            tau=prediction["tau"],
        ))
        if verdict in {"KNOWN_THREAT", "UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"}:
            grouped_incident_ids[event.event_id] = (prediction, risk_result, attack_probability)
    db.add_all(detection_rows)
    db.flush()
    for event in events:
        grouped = grouped_incident_ids.get(event.event_id)
        if grouped:
            prediction, risk_result, attack_probability = grouped
            if _should_suppress_borderline_flow_alert(event, prediction, risk_result, db,
                                                       host_context_by_event.get(event.event_id)):
                detection = db.query(DetectionResult).filter(DetectionResult.event_id == event.event_id).first()
                if detection:
                    details = dict(detection.details or {})
                    details["alert_status"] = "NOISE_SUPPRESSED"
                    details["suppression_reason"] = "Borderline network-only confidence without rule, endpoint, or user corroboration."
                    detection.details = details
                continue
            _upsert_grouped_flow_incident(event, prediction, bundle, risk_result, attack_probability, db)
    return counts


async def _save_and_broadcast_unscored(
    event_in: SecurityEventCreate,
    db: Session,
    db_event: SecurityEvent,
    event_id: str,
    reason: str,
    verdict: str = "NOT_COVERED",
) -> Dict[str, Any]:
    db.commit()
    result = _event_payload(event_in, event_id, verdict, reason=reason)
    await ws_manager.broadcast(result)
    return result


async def process_single_event(event_in: SecurityEventCreate, db: Session) -> Dict[str, Any]:
    """Persist every event; score only network events with named CICIDS features."""
    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    db_event = SecurityEvent(
        event_id=event_id,
        timestamp=event_in.timestamp,
        user_id=event_in.user_id,
        device_id=event_in.device_id,
        source_ip=event_in.source_ip,
        source_port=event_in.source_port,
        destination_ip=event_in.destination_ip,
        destination_port=event_in.destination_port,
        event_category=event_in.event_category,
        event_type=event_in.event_type,
        status=event_in.status,
        privilege_level=event_in.privilege_level,
        process_name=event_in.process_name,
        command_line=event_in.command_line,
        bytes_transferred=event_in.bytes_transferred,
        location=event_in.location,
        raw_payload=event_in.raw_payload,
        dataset=event_in.dataset,
    )
    db.add(db_event)
    host_context = (_update_live_host_context(db_event)
                    if event_in.event_category == "network" else {})

    if event_in.event_category == "endpoint":
        bundle = load_endpoint_bundle()
        if bundle is None:
            return await _save_and_broadcast_unscored(
                event_in, db, db_event, event_id, "endpoint behavioral model bundle is not ready",
                verdict="MODEL_NOT_READY",
            )
        try:
            features = extract_endpoint_features(event_in.raw_payload, event_in)
            prediction = predict_endpoint(features, bundle)
        except ValueError as exc:
            return await _save_and_broadcast_unscored(event_in, db, db_event, event_id, str(exc))
        score = prediction["s_endpoint"]
        user_prediction = None
        user_bundle = load_user_bundle() if event_in.user_id else None
        if user_bundle:
            user_prediction = _predict_user_event(db_event, user_bundle, db)
        graph_prediction = None
        endpoint_payload = event_in.raw_payload or {}
        source_host = event_in.source_ip or endpoint_payload.get("srcip")
        destination_host = event_in.destination_ip or endpoint_payload.get("dstip")
        graph_bundle = load_network_gat_bundle() if source_host and destination_host else None
        if graph_bundle:
            graph_features = dict(endpoint_payload)
            supplied_graph_features = endpoint_payload.get("network_graph_features", {})
            if isinstance(supplied_graph_features, dict):
                graph_features.update(supplied_graph_features)
            graph_prediction = predict_graph_edge(str(source_host), str(destination_host), graph_features, graph_bundle)
        verdict = "KNOWN_THREAT" if score >= 0.65 else "BENIGN"
        detection_id = f"det_{uuid.uuid4().hex[:12]}"
        db.add(DetectionResult(
            detection_id=detection_id, event_id=event_id, verdict=verdict,
            predicted_class="EndpointBehaviorAnomaly" if verdict == "KNOWN_THREAT" else "Baseline",
            probability=score, score=score, attack_probability=score,
            open_set_distance=None, reconstruction_error=prediction["reconstruction_error"],
            layer="endpoint", details={**prediction, "endpoint_features": features,
                **({"user_sequence": user_prediction} if user_prediction else {}),
                **({"network_graph": graph_prediction} if graph_prediction else {}),
                "score_name": "s_endpoint", "model_version": bundle["model_version"]},
            model_version=bundle["model_version"], tau=0.65,
        ))
        db.commit()
        result = _event_payload(event_in, event_id, verdict, detection_id=detection_id,
            predicted_class="EndpointBehaviorAnomaly" if verdict == "KNOWN_THREAT" else "Baseline",
            score=score, s_endpoint=score, score_name="s_endpoint",
            reconstruction_error=prediction["reconstruction_error"],
            feature_residuals=prediction["feature_residuals"],
            top_contributing_features=prediction["top_contributing_features"],
            model_version=bundle["model_version"], tau=0.65,
            **({"s_user": user_prediction["s_user"],
                "temporal_attention": user_prediction["temporal_attention"],
                "variable_selection_weights": user_prediction["variable_selection_weights"]}
               if user_prediction else {}),
            **({"s_network_graph": graph_prediction["s_network_graph"],
                "top_suspicious_edges": graph_prediction["top_suspicious_edges"]}
               if graph_prediction else {}))
        await ws_manager.broadcast(result)
        return result

    if event_in.event_category != "network":
        user_bundle = load_user_bundle() if event_in.user_id else None
        if user_bundle:
            user_prediction = _predict_user_event(db_event, user_bundle, db)
            score = user_prediction["s_user"]
            verdict = "KNOWN_THREAT" if score >= 0.65 else "BENIGN"
            detection_id = f"det_{uuid.uuid4().hex[:12]}"
            db.add(DetectionResult(
                detection_id=detection_id, event_id=event_id, verdict=verdict,
                predicted_class="AccountTakeoverRisk" if verdict == "KNOWN_THREAT" else "BaselineUserSequence",
                probability=score, score=score, attack_probability=score, open_set_distance=None,
                reconstruction_error=None, layer="user", details={**user_prediction,
                    "score_name": "s_user", "model_version": user_bundle["model_version"]},
                model_version=user_bundle["model_version"], tau=0.65,
            ))
            db.commit()
            result = _event_payload(event_in, event_id, verdict, detection_id=detection_id,
                predicted_class="AccountTakeoverRisk" if verdict == "KNOWN_THREAT" else "BaselineUserSequence",
                score=score, s_user=score, score_name="s_user",
                temporal_attention=user_prediction["temporal_attention"],
                variable_selection_weights=user_prediction["variable_selection_weights"],
                model_version=user_bundle["model_version"], tau=0.65)
            await ws_manager.broadcast(result)
            return result
        return await _save_and_broadcast_unscored(
            event_in, db, db_event, event_id, "no trained model for this layer"
        )

    payload = event_in.raw_payload or {}
    flow = payload.get("cicids_features")
    if not isinstance(flow, dict):
        return await _save_and_broadcast_unscored(
            event_in, db, db_event, event_id, "CICIDS2017 flow features are required"
        )
    flow_frame = pd.DataFrame([flow])
    add_protocol_invariant_features(flow_frame)
    add_service_port_buckets(flow_frame, [event_in.destination_port])
    flow = flow_frame.iloc[0].to_dict()
    flow.update(host_context)

    bundle = load_model_bundle()
    if bundle is None:
        logger.warning("CICIDS2017 LightGBM model bundle loader returned no bundle: %s", MODEL_BUNDLE_PATH)
        return await _save_and_broadcast_unscored(
            event_in, db, db_event, event_id, "CICIDS2017 model bundle is not ready",
            verdict="MODEL_NOT_READY",
        )

    feature_names = bundle["feature_names"]
    missing_features = [name for name in feature_names if name not in flow]
    if missing_features:
        return await _save_and_broadcast_unscored(
            event_in, db, db_event, event_id,
            f"CICIDS2017 flow features missing: {', '.join(missing_features[:5])}",
        )

    try:
        prediction = predict_flow(flow, bundle)
    except ValueError as exc:
        return await _save_and_broadcast_unscored(event_in, db, db_event, event_id, str(exc))
    class_names = prediction["class_names"]
    predicted_class = prediction["predicted_class"]
    score = prediction["score"]
    probability = prediction["probability"]
    tau = prediction["tau"]
    verdict = prediction["verdict"]

    benign_index = class_names.index("BENIGN") if "BENIGN" in class_names else None
    probabilities = prediction["probabilities"]
    attack_probability = float(1.0 - probabilities[benign_index])
    user_prediction = None
    if event_in.user_id:
        user_bundle = load_user_bundle()
        if user_bundle:
            user_prediction = _predict_user_event(db_event, user_bundle, db)
    graph_prediction = None
    source_host = event_in.source_ip or flow.get("srcip")
    destination_host = event_in.destination_ip or flow.get("dstip")
    if source_host and destination_host:
        graph_bundle = load_network_gat_bundle()
        if graph_bundle:
            graph_features = dict(flow)
            supplied_graph_features = (event_in.raw_payload or {}).get("network_graph_features", {})
            if isinstance(supplied_graph_features, dict):
                graph_features.update(supplied_graph_features)
            graph_prediction = predict_graph_edge(str(source_host), str(destination_host), graph_features, graph_bundle)
    fusion_inputs = {
        "s_user": user_prediction.get("s_user", 0.0) if user_prediction else 0.0,
        "s_endpoint": 0.0,
        "s_network_flow": attack_probability,
        "s_network_graph": graph_prediction.get("s_network_graph", 0.0) if graph_prediction else 0.0,
        "s_open_set_distance": prediction.get("open_set_score", prediction.get("centroid_distance", 0.0)),
        "stage_count": 1,
    }
    risk_result = compute_fused_risk(fusion_inputs)
    probability_by_class = prediction["probability_by_class"]
    detection_id = f"det_{uuid.uuid4().hex[:12]}"
    details = {
        "cicids_features": {name: float(flow[name]) for name in feature_names},
        "class_probabilities": probability_by_class,
        "score_name": bundle["score_name"],
        "score": score,
        "risk_breakdown": risk_result["breakdown"],
        "risk_fusion": {key: risk_result[key] for key in ("probability", "severity", "contributions", "inputs", "model_version", "calibrated")},
        "s_network_flow": attack_probability,
        "s_user": fusion_inputs["s_user"],
        "s_endpoint": fusion_inputs["s_endpoint"],
        "s_network_graph": fusion_inputs["s_network_graph"],
        "host_window": host_context,
        "s_open_set_distance": fusion_inputs["s_open_set_distance"],
        "open_set_score": prediction.get("open_set_score"),
        "centroid_distance": prediction.get("centroid_distance"),
        "open_set_label": prediction.get("open_set_label"),
        **({"user_sequence": user_prediction} if user_prediction else {}),
        **({"network_graph": graph_prediction} if graph_prediction else {}),
    }
    detection = DetectionResult(
        detection_id=detection_id,
        event_id=event_id,
        verdict=verdict,
        predicted_class=predicted_class,
        probability=probability,
        score=score,
        attack_probability=attack_probability,
        open_set_distance=prediction.get("centroid_distance"),
        reconstruction_error=None,
        layer="network",
        details=details,
        model_version=bundle["model_version"],
        tau=tau,
    )
    db.add(detection)

    mitre_mapping = {
        "BruteForce": ("Credential Access", "T1110"),
        "PortScan": ("Discovery", "T1046"),
        "DosDDoS": ("Impact", "T1498"),
    }.get(predicted_class)
    incident_id = None
    suppressed = _should_suppress_borderline_flow_alert(db_event, prediction, risk_result, db, host_context)
    if suppressed:
        details["alert_status"] = "NOISE_SUPPRESSED"
        details["suppression_reason"] = "Borderline network-only confidence without rule, endpoint, or user corroboration."
        detection.details = dict(details)
    if verdict in {"KNOWN_THREAT", "UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"} and not suppressed:
        incident_id = _upsert_grouped_flow_incident(
            db_event, prediction, bundle, risk_result, attack_probability, db
        )

    db.commit()
    result = _event_payload(
        event_in,
        event_id,
        verdict,
        detection_id=detection_id,
        predicted_class=predicted_class,
        probability=probability,
        score=score,
        score_name=bundle["score_name"],
        attack_probability=attack_probability,
        model_version=bundle["model_version"],
        tau=tau,
        probabilities=probability_by_class,
        incident_id=incident_id,
        risk_score=risk_result["score"],
        risk_breakdown=risk_result["breakdown"],
        mitre_mappings=[{"tactic": mitre_mapping[0], "technique_id": mitre_mapping[1]}]
        if incident_id and verdict == "KNOWN_THREAT" and mitre_mapping and probability >= settings.MITRE_MIN_PROBABILITY else [],
        s_network_flow=attack_probability,
        **({"s_user": user_prediction["s_user"],
            "temporal_attention": user_prediction["temporal_attention"],
            "variable_selection_weights": user_prediction["variable_selection_weights"]}
           if user_prediction else {}),
        **({"s_network_graph": graph_prediction["s_network_graph"],
            "top_suspicious_edges": graph_prediction["top_suspicious_edges"]}
           if graph_prediction else {}),
    )
    await ws_manager.broadcast(result)
    return result
