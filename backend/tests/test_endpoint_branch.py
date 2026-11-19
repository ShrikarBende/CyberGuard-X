"""Training, artifact, inference, and live endpoint routing coverage."""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database.session import Base
from app.detection import engine as detection_engine
from app.models import entities  # noqa: F401
from app.models.entities import DetectionResult
from app.schemas.schemas import SecurityEventCreate
from ml.endpoint_branch import (FEATURE_NAMES, extract_endpoint_features, generate_synthetic_endpoint_data,
                                parse_sysmon_json, predict_endpoint)
from ml.training.train_endpoint_branch import train_endpoint_branch


def _finish(coro):
    try:
        coro.send(None)
    except StopIteration as done:
        return done.value
    raise AssertionError("Expected synchronous completion")


def test_training_bundle_uses_benign_only_and_scores_attack(tmp_path):
    samples, labels = generate_synthetic_endpoint_data(180, seed=19)
    benign = samples[labels == 0]
    path = train_endpoint_branch(benign, tmp_path / "endpoint.pkl", epochs=15, seed=19)
    bundle = joblib.load(path)
    assert bundle["training_rows"] == len(benign)
    assert bundle["training_scope"] == "benign_baseline_only"
    assert len(bundle["feature_names"]) == len(FEATURE_NAMES)
    assert np.allclose(bundle["feature_min"], np.quantile(benign, .01, axis=0).astype(np.float32))
    normal = predict_endpoint(dict(zip(FEATURE_NAMES, benign[10])), bundle)
    attack = predict_endpoint(dict(zip(FEATURE_NAMES, samples[labels == 1][10])), bundle)
    assert 0 <= normal["s_endpoint"] <= 1
    assert attack["s_endpoint"] > normal["s_endpoint"]
    assert len(attack["top_contributing_features"]) == 5
    assert set(attack["feature_residuals"]) == set(FEATURE_NAMES)


def test_empty_sysmon_directory_uses_synthetic_fallback(tmp_path):
    bundle_path = train_endpoint_branch(output_path=tmp_path / "fallback.pkl", epochs=2,
                                        sysmon_dir=tmp_path / "empty-sysmon")
    bundle = joblib.load(bundle_path)
    assert bundle["training_source"] == "synthetic_fallback"
    assert bundle["training_rows"] == 1200


def test_feature_extractor_maps_sysmon_like_events():
    row = extract_endpoint_features({"parent_image": "WINWORD.EXE", "process_name": "powershell.exe",
                                     "privilege_escalation": True},
                                    SecurityEventCreate(event_type="ProcessCreate", event_category="endpoint"))
    assert row["process_creation_rate"] == 1
    assert row["parent_child_anomaly_rate"] == 1
    assert row["privilege_escalation_flags"] == 1


def test_real_sysmon_json_parser_extracts_event_id_features(tmp_path):
    capture = tmp_path / "sysmon.jsonl"
    records = [
        {"Event": {"System": {"EventID": 1}, "EventData": {"Data": [
            {"Name": "ParentImage", "#text": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"},
            {"Name": "Image", "#text": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            {"Name": "IntegrityLevel", "#text": "High"},
        ]}}},
        {"Event": {"System": {"EventID": 3}, "EventData": {"Data": []}}},
        {"Event": {"System": {"EventID": 8}, "EventData": {"Data": []}}},
        {"Event": {"System": {"EventID": 10}, "EventData": {"Data": []}}},
        {"Event": {"System": {"EventID": 11}, "EventData": {"Data": []}}},
        {"Event": {"System": {"EventID": 13}, "EventData": {"Data": []}}},
    ]
    import json
    capture.write_text("\n".join(json.dumps(item) for item in records), encoding="utf-8")
    row = parse_sysmon_json(capture)[0]
    features = dict(zip(FEATURE_NAMES, row))
    assert features["process_creation_rate"] == 1
    assert features["parent_child_anomaly_rate"] == 1
    assert features["privilege_escalation_flags"] == 3
    assert features["network_connection_count"] == 1
    assert features["file_write_count"] == 1
    assert features["registry_write_count"] == 1


def test_live_endpoint_event_is_persisted_with_endpoint_score(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    _, labels = generate_synthetic_endpoint_data(100, seed=23)
    samples, _ = generate_synthetic_endpoint_data(100, seed=23)
    bundle_path = train_endpoint_branch(samples[labels == 0], tmp_path / "endpoint.pkl", epochs=8, seed=23)
    bundle = joblib.load(bundle_path)
    monkeypatch.setattr(detection_engine, "load_endpoint_bundle", lambda: bundle)
    with factory() as db:
        result = _finish(detection_engine.process_single_event(SecurityEventCreate(
            event_type="ProcessCreate", event_category="endpoint", process_name="powershell.exe",
            raw_payload={"endpoint_features": dict(zip(FEATURE_NAMES, samples[-1].astype(float)))},
        ), db))
        saved = db.query(DetectionResult).one()
        assert result["score_name"] == "s_endpoint"
        assert result["s_endpoint"] == result["score"]
        assert len(result["feature_residuals"]) == len(FEATURE_NAMES)
        assert saved.layer == "endpoint"
    engine.dispose()
