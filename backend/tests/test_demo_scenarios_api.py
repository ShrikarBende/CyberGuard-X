from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timezone
import json
from collections import Counter

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.api.endpoints import delete_demo_events, load_demo_scenarios
from app.database.session import Base
from app.ingestion.scenarios import generate_demo_events
from app.models.entities import (
    AnalystAccount, AnalystActivity, Device, SecurityEvent, User,
)


@pytest.fixture
def demo_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'demo.sqlite'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False)
    session = factory()
    admin = AnalystAccount(
        account_id="admin-demo-test",
        username="demo-admin",
        password_hash="test-hash",
        role="admin",
    )
    session.add(admin)
    session.commit()
    try:
        yield session, admin
    finally:
        session.close()
        engine.dispose()


def test_demo_loader_inserts_unique_entities_and_second_load_is_idempotent(demo_session):
    session, admin = demo_session
    expected = generate_demo_events()
    expected_user_ids = {event["user_id"] for event in expected if event.get("user_id")}
    expected_device_ids = {event["device_id"] for event in expected if event.get("device_id")}

    result = load_demo_scenarios(session, admin)
    assert result["status"] == "loaded"
    assert result["events_inserted"] == len(expected)
    loaded_events = session.query(SecurityEvent).filter(
        SecurityEvent.dataset == "synthetic_demo"
    ).all()
    assert len(loaded_events) == len(expected)
    assert Counter(event.scenario for event in loaded_events) == Counter(event["scenario"] for event in expected)
    assert session.query(User).filter(User.user_id.in_(expected_user_ids)).count() == len(expected_user_ids)
    assert session.query(Device).filter(Device.device_id.in_(expected_device_ids)).count() == len(expected_device_ids)

    second = load_demo_scenarios(session, admin)
    assert second == {"status": "already_loaded", "events": len(expected)}
    assert session.query(SecurityEvent).filter(SecurityEvent.dataset == "synthetic_demo").count() == len(expected)


def test_reset_removes_only_demo_rows_and_unused_demo_entities(demo_session):
    session, admin = demo_session
    non_demo_user = User(user_id="human-user", username="human", role="analyst")
    non_demo_device = Device(device_id="human-device", hostname="human-device", os="Windows")
    non_demo_event = SecurityEvent(
        event_id="human-event", timestamp=datetime.now(timezone.utc),
        user_id=non_demo_user.user_id, device_id=non_demo_device.device_id,
        event_category="auth", event_type="login_success", dataset="manual_upload",
    )
    session.add_all([non_demo_user, non_demo_device, non_demo_event])
    session.commit()
    expected_count = len(generate_demo_events())
    load_demo_scenarios(session, admin)

    result = delete_demo_events(session, admin)
    assert result["status"] == "deleted"
    assert result["events"] == expected_count
    assert session.query(SecurityEvent).filter(SecurityEvent.dataset == "synthetic_demo").count() == 0
    assert session.query(SecurityEvent.event_id).filter(SecurityEvent.event_id == "human-event").first()
    assert session.query(User.user_id).filter(User.user_id == "human-user").first()
    assert session.query(Device.device_id).filter(Device.device_id == "human-device").first()
    assert session.query(User).filter(User.role == "demo").count() == 0
    assert session.query(Device).filter(Device.os == "Synthetic demo").count() == 0
    actions = {row.action_type for row in session.query(AnalystActivity).all()}
    assert {"demo_load", "demo_reset"} <= actions


def test_loaded_demo_events_produce_one_takeover_incident_when_correlated(demo_session):
    session, admin = demo_session
    load_demo_scenarios(session, admin)
    from app.correlation.engine import run_correlation

    result = run_correlation(session)
    assert len(result["incidents"]) == 1
    assert "multi_stage_takeover" in {
        event.scenario for event in session.query(SecurityEvent).filter(
            SecurityEvent.event_id.in_([
                association.event_id for association in result["incidents"][0].events
            ])
        ).all()
    }


def test_unexpected_exception_response_exposes_details_only_in_dev(monkeypatch):
    from app.core.config import settings
    from app.main import unexpected_exception_response

    request = Request({"type": "http", "method": "GET", "path": "/test", "headers": []})
    monkeypatch.setattr(settings, "APP_ENV", "dev")
    dev_response = unexpected_exception_response(request, ValueError("diagnostic detail"))
    assert dev_response.status_code == 500
    assert json.loads(dev_response.body) == {"detail": "ValueError: diagnostic detail"}
    monkeypatch.setattr(settings, "APP_ENV", "production")
    prod_response = unexpected_exception_response(request, ValueError("private detail"))
    assert json.loads(prod_response.body) == {"detail": "Internal server error."}
