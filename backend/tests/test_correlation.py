from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.correlation.engine import correlate_events
from app.ingestion.scenarios import generate_demo_events
from ml import fusion_meta


@pytest.fixture(autouse=True)
def use_fusion_fallback_for_correlation_tests(monkeypatch):
    # These rules tests exercise the deterministic fallback, not repository artifacts.
    monkeypatch.setattr(fusion_meta, "_BUNDLE_CACHE", {})


def _scenario(name: str):
    fixed_now = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
    return [event for event in generate_demo_events(fixed_now) if event["scenario"] == name]


def test_takeover_produces_one_incident_with_ordered_stages():
    result = correlate_events(_scenario("multi_stage_takeover"))
    assert len(result["incidents"]) == 1
    stages = [stage["stage"] for stage in result["incidents"][0]["indicators"]]
    assert stages == [
        "failed_login_burst",
        "new_ip_login",
        "off_hours_login",
        "privilege_escalation",
        "encoded_powershell",
        "rare_port_outbound",
        "large_transfer",
    ]


def test_brute_force_alone_is_an_alert_without_incident():
    result = correlate_events(_scenario("brute_force_only"))
    assert [alert["name"] for alert in result["alerts"]] == ["failed_login_burst"]
    assert result["incidents"] == []


def test_benign_admin_is_flagged_as_alert_only():
    result = correlate_events(_scenario("benign_admin"))
    # Flagged: privilege escalation and large-transfer rules match; no incident because
    # this benign maintenance flow has only two distinct indicator types, below the 3-type rule.
    assert {alert["name"] for alert in result["alerts"]} == {
        "privilege_escalation", "large_transfer"
    }
    assert result["incidents"] == []


def test_normal_employee_day_produces_nothing():
    result = correlate_events(_scenario("normal_employee_day"))
    assert result == {"alerts": [], "incidents": [], "window_minutes": 60.0}


def test_unrelated_users_are_never_merged():
    events = _scenario("brute_force_only") + _scenario("benign_admin")
    result = correlate_events(events)
    assert len(result["alerts"]) == 3
    assert result["incidents"] == []


def test_shorter_window_splits_takeover_correlation():
    events = _scenario("multi_stage_takeover")
    normal_window = correlate_events(events, window_minutes=60)
    short_window = correlate_events(events, window_minutes=3)
    assert len(normal_window["incidents"]) == 1
    assert short_window["incidents"] == []
    assert len(short_window["alerts"]) == len(normal_window["alerts"])
