"""
End-to-End API Test Suite for Enterprise CyberGuard X.
"""
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.main import app

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows TestClient requests hang during asyncio self-pipe initialization in this environment; verify API routes against a running server instead.",
)

client = TestClient(app)


def test_health_check():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_dashboard_stats():
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "threat_distribution" in data
    assert "risk_trend" in data
    assert "layer_detection_stats" in data


def test_get_events():
    res = client.get("/api/events?limit=10")
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    assert len(events) > 0


def test_get_incidents_and_detail():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert len(incidents) > 0

    inc_id = incidents[0]["incident_id"]
    detail_res = client.get(f"/api/incidents/{inc_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["incident_id"] == inc_id


def test_threat_intelligence():
    res = client.get("/api/threats")
    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "known_categories" in data
    assert "unknown_novel_threats" in data


def test_explainability():
    res = client.get("/api/incidents")
    inc_id = res.json()[0]["incident_id"]

    exp_res = client.get(f"/api/explainability/{inc_id}")
    assert exp_res.status_code == 200
    data = exp_res.json()
    assert "shap_feature_importance" in data
    assert "layer_breakdown" in data


def test_rag_chat():
    payload = {
        "query": "What attack technique is involved and what are the containment steps?"
    }
    res = client.post("/api/rag/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "answer" in data
    assert "citations" in data
    assert len(data["citations"]) > 0


def test_models_status():
    res = client.get("/api/models/status")
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert data["models"]["isolation_forest"]["is_trained"] is True
    assert data["models"]["xgboost_classifier"]["is_trained"] is True
    assert data["models"]["denoising_autoencoder"]["is_trained"] is True

