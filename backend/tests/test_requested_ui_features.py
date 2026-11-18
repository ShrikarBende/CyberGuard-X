"""Regression checks for replay, review queue, and the evaluation summary UI."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.routing import APIRoute
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.api.endpoints import get_incidents
from app.database.session import Base
from app.main import app
from app.models.entities import Incident


def test_demo_replay_start_status_and_stop_routes_exist():
    route_methods = {
        (route.path, method)
        for route in app.routes if isinstance(route, APIRoute)
        for method in (route.methods or ())
    }
    assert ("/api/demo/replay", "POST") in route_methods
    assert ("/api/demo/replay/status", "GET") in route_methods
    assert ("/api/demo/replay/stop", "POST") in route_methods


def test_review_queue_returns_only_needs_review_incidents(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'review-queue.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    try:
        session.add_all([
            Incident(incident_id="needs-review", title="Review", severity="MEDIUM",
                     status="NEEDS_REVIEW", threat_classification="UNKNOWN_CANDIDATE",
                     overall_risk_score=10),
            Incident(incident_id="open", title="Open", severity="LOW",
                     status="OPEN", threat_classification="KNOWN_THREAT",
                     overall_risk_score=5),
        ])
        session.commit()
        rows = get_incidents(status="NEEDS_REVIEW", limit=50, db=session)
        assert [row.incident_id for row in rows] == ["needs-review"]
    finally:
        session.close()
        engine.dispose()

    ui = (PROJECT_ROOT / "frontend" / "src" / "pages" / "IncidentManagement.jsx").read_text(encoding="utf-8")
    assert "incident.status === 'NEEDS_REVIEW'" in ui
    assert "Model review queue" in ui


def test_evaluation_page_loads_summary_through_api_client():
    page = (PROJECT_ROOT / "frontend" / "src" / "pages" / "Evaluation.jsx").read_text(encoding="utf-8")
    api_client = (PROJECT_ROOT / "frontend" / "src" / "services" / "api.js").read_text(encoding="utf-8")
    assert "api.getEvaluationSummary()" in page
    assert "fetchJson('/evaluation/summary')" in api_client


def test_tests_default_evaluation_outputs_outside_saved_results(monkeypatch):
    import os
    from ml.evaluation import known_classifier, open_set_pipeline

    configured = Path(os.environ["CYBERGUARDX_TEST_RESULTS_DIR"]).resolve()
    saved_results = (BACKEND_DIR / "ml" / "evaluation" / "results").resolve()
    assert configured != saved_results
    assert saved_results not in configured.parents
    assert known_classifier.RESULTS_DIR == configured
    assert open_set_pipeline.RESULTS_DIR == configured
    assert open_set_pipeline.RESULTS_DIR / "scores" == configured / "scores"


def test_real_evaluation_run_defaults_to_saved_results_even_under_pytest():
    from ml.evaluation.output_paths import DEFAULT_RESULTS_DIR, get_results_dir

    expected = (BACKEND_DIR / "ml" / "evaluation" / "results").resolve()
    assert DEFAULT_RESULTS_DIR == expected
    assert get_results_dir(test_mode=False) == expected
