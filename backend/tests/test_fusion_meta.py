"""Risk fusion calibration, persistence compatibility, and explainability tests."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.api.endpoints import get_explainability
from app.database.session import Base
from app.models.entities import DetectionResult, Incident, IncidentEvent, RiskScore, SecurityEvent
from ml.fusion_meta import severity_tier, predict_fused_risk
from ml.training.train_fusion_meta import train_fusion_meta


@pytest.mark.parametrize("probability,tier", [
    (0.0, "LOW"), (0.249, "LOW"), (0.25, "MEDIUM"),
    (0.5, "HIGH"), (0.75, "CRITICAL"), (1.0, "CRITICAL"),
])
def test_probability_maps_to_severity_tier(probability, tier):
    assert severity_tier(probability) == tier


def test_fusion_meta_training_is_calibrated_and_contributions_normalize(tmp_path):
    artifact = tmp_path / "fusion.joblib"
    train_fusion_meta(output_path=artifact)
    import joblib
    bundle = joblib.load(artifact)
    assert bundle["calibrated"] is True
    assert bundle["validation_metrics"]["validation_brier_score"] < 0.3
    result = predict_fused_risk({
        "s_user": 0.8, "s_endpoint": 0.7, "s_network_flow": 0.9,
        "s_network_graph": 0.85, "s_open_set_distance": 0.75, "stage_count": 5,
    }, bundle)
    assert 0.0 <= result["probability"] <= 1.0
    assert result["severity"] == severity_tier(result["probability"])
    assert set(result["contributions"]) == {
        "user_contribution", "endpoint_contribution", "network_contribution", "open_set_contribution"
    }
    assert sum(result["contributions"].values()) == pytest.approx(100.0)


def test_fusion_risk_persists_using_existing_schema_and_migrations(tmp_path):
    from app.main import run_database_migrations
    db_path = tmp_path / "fusion-migration.db"
    engine = create_engine(f"sqlite:///{db_path}")
    try:
        run_database_migrations(engine)
        columns = {item["name"] for item in inspect(engine).get_columns("risk_scores")}
        assert {"score", "category", "user_risk_component", "endpoint_risk_component",
                "network_risk_component", "risk_breakdown"}.issubset(columns)
        assert "risk_scores" in Base.metadata.tables
    finally:
        engine.dispose()


def test_explainability_returns_fusion_and_multimodal_payload(tmp_path, monkeypatch):
    from app.detection import engine as detection_engine
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: None)
    engine = create_engine(f"sqlite:///{tmp_path / 'explain.db'}")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, autoflush=False)()
    try:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        incident = Incident(
            incident_id="fusion-explain", title="Multi-layer incident", severity="HIGH",
            status="OPEN", threat_classification="RULE_CORRELATED_SUSPICIOUS_ACTIVITY",
            overall_risk_score=63.0, first_detected_at=now, last_updated_at=now,
            evidence={"risk_fusion": {"probability": 0.63, "severity": "HIGH",
                                      "contributions": {"user_contribution": 20.0,
                                                        "endpoint_contribution": 30.0,
                                                        "network_contribution": 35.0,
                                                        "open_set_contribution": 15.0}}},
        )
        event = SecurityEvent(event_id="fusion-event", timestamp=now, event_category="endpoint",
                              event_type="process_creation", status="success")
        db.add_all([incident, event]); db.flush()
        db.add_all([
            IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id, stage="execution", order=0),
            RiskScore(incident_id=incident.incident_id, score=63.0, category="HIGH",
                      user_risk_component=20.0, endpoint_risk_component=30.0,
                      network_risk_component=35.0, risk_breakdown={"fusion": incident.evidence["risk_fusion"]}),
            DetectionResult(detection_id="fusion-detection", event_id=event.event_id,
                            verdict="UNKNOWN_NOVEL", predicted_class="PortScan", probability=.8,
                            score=.9, attack_probability=.9, open_set_distance=4.0,
                            reconstruction_error=.2, layer="endpoint",
                            details={"s_endpoint": .9, "feature_residuals": {"privilege": .8},
                                     "top_contributing_features": [{"feature": "privilege", "residual": .8}],
                                     "open_set_score": .85, "open_set_label": "UNKNOWN_NOVEL",
                                     "user_sequence": {"temporal_attention": [.2, .8]},
                                     "network_graph": {"s_network_graph": .7,
                                                       "top_suspicious_edges": [{"srcip": "a", "dstip": "b", "attention": .9}]} }),
        ])
        db.commit()
        response = get_explainability(incident.incident_id, db)
        assert response["available"] is True
        assert response["calibrated_risk_score"] == pytest.approx(.63)
        assert response["severity"] == "HIGH"
        assert sum(response["per_layer_contributions"].values()) == pytest.approx(100.0)
        assert response["explanations"]["endpoint_reconstruction_residuals"]
        assert response["explanations"]["user_temporal_attention"]
        assert response["explanations"]["network_graph_edge_attention"]
        assert response["explanations"]["open_set_novelty"][0]["flagged"] is True
        assert response["explanations"]["tree_shap_feature_attributions"] == []
    finally:
        db.close()
        engine.dispose()
