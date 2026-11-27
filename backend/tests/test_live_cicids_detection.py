"""Focused tests for CICIDS thresholding, coverage, and artifact inference."""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database.session import Base
from app.detection import engine as detection_engine
from app.models import entities  # noqa: F401
from app.models.entities import DetectionResult, Incident, MitreTechnique, SecurityEvent
from app.schemas.schemas import SecurityEventCreate
from ml.preprocessing.cicids_pipeline import apply_log1p_columns, build_full_pipeline
from ml.training.train_final import ARTIFACT_PATH, compute_margin_tau
from ml import fusion_meta


@pytest.fixture(autouse=True)
def use_fusion_fallback_without_loading_repository_artifacts(tmp_path, monkeypatch):
    """Keep flow tests isolated from the unsigned checked-in Fusion bundle."""
    monkeypatch.setattr(fusion_meta, "ARTIFACT_PATH", tmp_path / "no-signed-fusion.joblib")
    monkeypatch.setattr(fusion_meta, "_BUNDLE_CACHE", None)


def _finish_inline(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Expected detector coroutine to complete without an event loop")


@pytest.fixture
def db_session():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    session_factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    with session_factory() as db:
        yield db
    test_engine.dispose()


def test_auth_event_is_not_covered(db_session, monkeypatch):
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: None)
    result = _finish_inline(detection_engine.process_single_event(
        SecurityEventCreate(event_type="login", event_category="auth"), db_session
    ))
    assert result["verdict"] == "NOT_COVERED"
    assert result["reason"] == "no trained model for this layer"
    assert result["incident_id"] is None
    assert result["risk_score"] is None
    assert result["mitre_mappings"] == []
    assert db_session.query(DetectionResult).count() == 0


def test_probability_below_tau_is_unknown_candidate(db_session, monkeypatch):
    class IdentityScaler:
        def transform(self, values):
            return values

    class LowConfidenceModel:
        def predict(self, values, raw_score=False):
            return np.tile(np.array([[0.60, 0.40]]), (len(values), 1))

        def predict_proba(self, values):
            return np.tile(np.array([[0.60, 0.40]]), (len(values), 1))

    bundle = {
        "model": LowConfidenceModel(),
        "scaler": IdentityScaler(),
        "feature_names": ["flow_a", "flow_b"],
        "log1p_columns": [False, False],
        "class_names": ["BENIGN", "PortScan"],
        "tau": 0.70,
        "score_name": "logit_margin",
        "model_version": "unit-test-model",
    }
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: bundle)
    result = _finish_inline(detection_engine.process_single_event(
        SecurityEventCreate(
            event_type="cicids_flow",
            event_category="network",
            raw_payload={"cicids_features": {"flow_a": 1.0, "flow_b": 2.0}},
        ),
        db_session,
    ))
    assert result["verdict"] == "UNKNOWN_CANDIDATE"
    assert result["predicted_class"] == "BENIGN"
    assert result["probabilities"]["BENIGN"] == pytest.approx(0.60)
    assert result["tau"] == pytest.approx(0.70)
    assert result["model_version"] == "unit-test-model"
    saved_detection = db_session.query(DetectionResult).one()
    assert saved_detection.model_version == "unit-test-model"
    assert saved_detection.tau == pytest.approx(0.70)
    assert saved_detection.predicted_class == "BENIGN"
    assert saved_detection.probability == pytest.approx(0.60)
    assert result["score"] == pytest.approx(0.20)
    assert result["attack_probability"] == pytest.approx(0.40)
    assert "confidence" not in result
    assert "anomaly_score" not in result
    assert saved_detection.score == pytest.approx(0.20)
    assert saved_detection.attack_probability == pytest.approx(0.40)
    assert saved_detection.confidence is None
    assert saved_detection.anomaly_score is None
    review = db_session.query(Incident).one()
    assert review.threat_classification == "UNKNOWN_CANDIDATE"
    assert review.status == "NEEDS_REVIEW"
    assert review.description == "Low model margin; not a confirmed novel attack."
    assert review.evidence["risk_breakdown"]
    from app.api.endpoints import get_incidents
    assert [row.incident_id for row in get_incidents(status="NEEDS_REVIEW", limit=50, db=db_session)] == [review.incident_id]


def test_known_threat_flows_group_and_keep_sample_event_cap(db_session, monkeypatch):
    from datetime import datetime, timezone
    from app.models.entities import IncidentEvent, RiskScore

    class IdentityScaler:
        def transform(self, values):
            return values

    class StrongThreatModel:
        def predict(self, values, raw_score=False):
            return np.tile(np.array([[0.0, 10.0]]), (len(values), 1))

        def predict_proba(self, values):
            return np.tile(np.array([[0.1, 0.9]]), (len(values), 1))

    bundle = {
        "model": StrongThreatModel(), "scaler": IdentityScaler(),
        "feature_names": ["flow_a", "flow_b"], "log1p_columns": [False, False],
        "class_names": ["BENIGN", "PortScan"], "tau": 1.0,
        "score_name": "logit_margin", "model_version": "unit-test-model",
    }
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: bundle)
    monkeypatch.setattr(detection_engine.settings, "INCIDENT_WINDOW_MINUTES", 5)
    for second in (10, 20):
        _finish_inline(detection_engine.process_single_event(SecurityEventCreate(
            timestamp=datetime(2026, 1, 2, 3, 4, second, tzinfo=timezone.utc),
            source_ip="198.51.100.7", event_type="cicids_flow", event_category="network",
            raw_payload={"cicids_features": {"flow_a": 1.0, "flow_b": 2.0}},
        ), db_session))
    incident = db_session.query(Incident).one()
    assert incident.flow_count == 2
    assert incident.threat_classification == "KNOWN_THREAT"
    assert db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.incident_id).count() == 2
    assert incident.evidence["score_summary"]["count"] == 2
    assert db_session.query(RiskScore).one().risk_breakdown


def test_mitre_mapping_uses_probability_gate_not_margin_tau(db_session, monkeypatch):
    class IdentityScaler:
        def transform(self, values):
            return values

    class StrongMarginModel:
        def predict(self, values, raw_score=False):
            return np.tile(np.array([[0.0, 10.0]]), (len(values), 1))

        def predict_proba(self, values):
            return np.tile(np.array([[0.35, 0.65]]), (len(values), 1))

    bundle = {
        "model": StrongMarginModel(),
        "scaler": IdentityScaler(),
        "feature_names": ["flow_a", "flow_b"],
        "log1p_columns": [False, False],
        "class_names": ["BENIGN", "PortScan"],
        "tau": 1.0,
        "score_name": "logit_margin",
        "model_version": "unit-test-model",
    }
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: bundle)
    monkeypatch.setattr(detection_engine.settings, "MITRE_MIN_PROBABILITY", 0.7)
    response = _finish_inline(detection_engine.process_single_event(
        SecurityEventCreate(
            event_type="cicids_flow",
            event_category="network",
            raw_payload={"cicids_features": {"flow_a": 1.0, "flow_b": 2.0}},
        ),
        db_session,
    ))
    assert response["score"] >= response["tau"]
    assert response["probability"] == pytest.approx(0.65)
    assert response["verdict"] == "KNOWN_THREAT"
    assert response["mitre_mappings"] == []
    assert db_session.query(Incident).count() == 1
    assert db_session.query(MitreTechnique).count() == 0


def test_tau_rejects_unknown_validation_rows():
    scores = np.array([[0.99, 0.01], [0.80, 0.20], [0.60, 0.40], [0.40, 0.60]])
    margins = np.diff(np.sort(scores, axis=1), axis=1)[:, 0]
    tau = compute_margin_tau(scores, ["BENIGN", "BENIGN", "PortScan", "PortScan"], ["BENIGN", "PortScan"])
    assert tau == pytest.approx(np.quantile(margins, 0.05))
    with pytest.raises(ValueError, match="known-class"):
        compute_margin_tau(
            np.vstack([scores, [0.5, 0.5]]),
            ["BENIGN", "BENIGN", "PortScan", "PortScan", "UNKNOWN_FAMILY"],
            ["BENIGN", "PortScan"],
        )


@pytest.mark.requires_data(reason="Requires the trained CICIDS bundle and real CICIDS test rows.")
def test_real_artifact_loads_and_predicts_on_five_test_rows(db_session, monkeypatch):
    assert ARTIFACT_PATH.is_file(), "Run train_final.py to create the real CICIDS bundle first."
    bundle = joblib.load(ARTIFACT_PATH)
    pipeline = build_full_pipeline(seed=42, sample=0.15, log1p=True)
    # Keep the saved provenance hash visible without requiring a checked-in
    # artifact to match a dataset/cache that may have changed since training.
    assert isinstance(bundle["data_hash"], str) and bundle["data_hash"]
    raw = pipeline["test_df"][bundle["feature_names"]].head(5).to_numpy(dtype=np.float32)
    transformed = apply_log1p_columns(raw, np.asarray(bundle["log1p_columns"], dtype=bool))
    scaled = bundle["scaler"].transform(transformed)
    probabilities = bundle["model"].predict_proba(scaled)
    raw_scores = bundle["model"].predict(scaled, raw_score=True)
    assert probabilities.shape == (5, len(bundle["class_names"]))
    assert raw_scores.shape == (5, len(bundle["class_names"]))
    assert bundle["score_name"] == "logit_margin"
    assert np.isfinite(probabilities).all()

    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: bundle)
    first_flow = {name: float(value) for name, value in zip(bundle["feature_names"], raw[0])}
    response = _finish_inline(detection_engine.process_single_event(
        SecurityEventCreate(
            event_type="cicids2017_flow",
            event_category="network",
            dataset="cicids2017_replay",
            raw_payload={"cicids_features": first_flow},
        ),
        db_session,
    ))
    assert response["model_version"] == bundle["model_version"]
    assert response["tau"] == pytest.approx(bundle["tau"])
    assert response["probabilities"]
    persisted = db_session.query(DetectionResult).one()
    assert persisted.probability == pytest.approx(response["probability"])
    assert response["score_name"] == "logit_margin"
    assert persisted.model_version == bundle["model_version"]
    assert persisted.tau == pytest.approx(bundle["tau"])
    assert db_session.query(SecurityEvent).one().dataset == "cicids2017_replay"
