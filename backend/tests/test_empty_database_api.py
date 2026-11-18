"""API behavior with a clean database and no trained detection artifacts."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database.session import Base
from app.api.endpoints import get_dashboard_stats, get_incidents, get_threat_intelligence, analyze_event
from app.models.entities import DetectionResult, Incident
from app.schemas.schemas import SecurityEventCreate


def test_empty_database_and_missing_model_bundle_fails_clearly(tmp_path, monkeypatch):
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'empty.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    from app.detection import engine as detection_engine
    detection_engine._MODEL_BUNDLE_CACHE = None
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", tmp_path / "missing_model.bundle.pkl")

    try:
        with TestSession() as db:
            stats = get_dashboard_stats(db)
            assert stats.total_detections == 0
            assert stats.risk_trend == []
            assert stats.threat_distribution == []
            assert get_incidents(limit=50, db=db) == []
            threats = get_threat_intelligence(db)
            assert threats["detection_count"] == 0
            assert threats["known_categories"] == []
            assert threats["unknown_candidates"] == []

            coroutine = analyze_event(
                SecurityEventCreate(
                    event_type="raw_test_event",
                    event_category="network",
                    raw_payload={"cicids_features": {}},
                ),
                db,
            )
            with pytest.raises(FileNotFoundError, match="no alternate bundle"):
                coroutine.send(None)
            db.rollback()
            assert get_incidents(limit=50, db=db) == []
            assert db.query(Incident).count() == 0
            assert db.query(DetectionResult).count() == 0
    finally:
        detection_engine._MODEL_BUNDLE_CACHE = None
        test_engine.dispose()
