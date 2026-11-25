from datetime import datetime, timezone
from app.agent.tools import ARG_MODELS, ToolRegistry
from app.models.entities import Incident, IncidentEvent, SecurityEvent, DetectionResult, RiskScore


def test_tool_schemas_constrain_high_risk_arguments_and_describe_each_tool(db_pair):
    registry = ToolRegistry()
    schemas = registry.schemas_for(list(ARG_MODELS))
    by_name = {item["function"]["name"]: item["function"] for item in schemas}
    assert by_name["find_related_events"]["parameters"]["properties"]["field"]["enum"] == [
        "user_id", "device_id", "source_ip", "destination_ip"]
    assert by_name["search_knowledge"]["parameters"]["properties"]["source_types"]["items"]["enum"] == [
        "mitre", "playbook", "past_incident"]
    assert by_name["propose_action"]["parameters"]["properties"]["action_type"]["enum"]
    assert by_name["propose_action"]["parameters"]["properties"]["confidence"]["exclusiveMinimum"] == 0
    descriptions = [item["description"] for item in by_name.values()]
    assert len(set(descriptions)) == len(descriptions)
    assert all(len(description) >= 40 and "evidence" in description.lower() for description in descriptions)


def test_invalid_tool_enum_returns_clean_error(db_pair):
    db, _ = db_pair
    incident = Incident(incident_id="schema-i", title="test", status="OPEN", severity="LOW",
        threat_classification="UNKNOWN", overall_risk_score=0, flow_count=0,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    db.add(incident); db.commit()
    result = ToolRegistry().run("find_related_events", {"field": "password", "value": "x"},
        db, incident, "r", "analyst", set())
    assert result.ok is False
    assert result.error.startswith("invalid tool arguments:")


def test_explanation_is_read_only_distinct_and_filters_raw_detector_features(db_pair):
    db, _ = db_pair
    incident = Incident(incident_id="explain-i", title="test", status="OPEN", severity="HIGH",
        threat_classification="UNKNOWN", overall_risk_score=80, flow_count=1,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    event = SecurityEvent(event_id="explain-e", timestamp=datetime.now(timezone.utc), event_category="network",
        event_type="flow", raw_payload={"safe": "telemetry"})
    db.add_all([incident, event]); db.flush()
    db.add(IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id))
    db.add(DetectionResult(detection_id="explain-d", event_id=event.event_id, verdict="UNKNOWN_CANDIDATE",
        predicted_class="unknown", layer="network", details={"top_contributing_features": [{"feature": str(i)} for i in range(12)],
        "cicids_features": {"secret_feature": 999}, "risk_breakdown": {"network": 80}}))
    db.add(RiskScore(incident_id=incident.incident_id, score=80, category="HIGH",
        top_contributing_features=[{"feature": "x", "value": .8}], explanation_summary="Network evidence dominates.",
        risk_breakdown={"fusion": {"probability": .8}}))
    db.commit()
    registry = ToolRegistry()
    before = db.query(RiskScore).one().top_contributing_features
    evidence = registry.run("get_incident_evidence", {"incident_id": incident.incident_id}, db, incident, "r", "analyst", set())
    explanation = registry.run("get_explanation", {"incident_id": incident.incident_id}, db, incident, "r", "analyst", set())
    assert explanation.data != evidence.data
    assert explanation.data["explanation_summary"] == "Network evidence dominates."
    assert len(explanation.data["detections"][0]["details"]["top_contributing_features"]) == 10
    assert "cicids_features" not in str(explanation.data)
    assert not db.new and not db.dirty and not db.deleted
    assert db.query(RiskScore).one().top_contributing_features == before


def test_related_events_window_is_anchored_to_replayed_incident_time(db_pair):
    from datetime import timedelta
    from app.models.entities import IncidentEvent, SecurityEvent
    from app.agent.tools import RelatedArgs
    db, _ = db_pair
    first = datetime(2024, 5, 1, tzinfo=timezone.utc)
    incident = Incident(incident_id="old-i", title="replay", status="OPEN", severity="LOW",
        threat_classification="UNKNOWN", overall_risk_score=1, flow_count=1,
        first_detected_at=first, last_updated_at=first + timedelta(minutes=30))
    own = SecurityEvent(event_id="old-own", timestamp=first, source_ip="192.0.2.77", event_category="network", event_type="flow")
    related = SecurityEvent(event_id="old-related", timestamp=first + timedelta(minutes=10), source_ip="192.0.2.77",
        event_category="network", event_type="flow")
    db.add_all([incident, own, related]); db.flush()
    db.add(IncidentEvent(incident_id=incident.incident_id, event_id=own.event_id)); db.commit()
    result = ToolRegistry()._find_related_events(RelatedArgs(field="source_ip", value="192.0.2.77", window_minutes=60),
        db, incident)
    assert {item["event_id"] for item in result.data} == {"old-own", "old-related"}


def test_result_truncation_keeps_json_and_only_cites_visible_event_items(db_pair, monkeypatch):
    import json
    from app.agent.tools import ToolResult
    db, _ = db_pair
    incident = Incident(incident_id="truncate-i", title="test", status="OPEN", severity="LOW",
        threat_classification="UNKNOWN", overall_risk_score=1, flow_count=0,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    db.add(incident); db.commit()
    registry = ToolRegistry()
    registry.handlers["get_incident_evidence"] = lambda *args: ToolResult(
        [{"event_id": f"e{index}", "payload": "x" * 300} for index in range(200)],
        [f"evt:e{index}" for index in range(200)])
    monkeypatch.setattr("app.agent.tools.settings.AGENT_RESULT_CHARS", 1200)
    result = registry.run("get_incident_evidence", {"incident_id": incident.incident_id}, db,
        incident, "r", "analyst", set())
    wrapper = {"ok": result.ok, "evidence_ids": result.evidence_ids, "data": result.data}
    encoded = json.dumps(wrapper, ensure_ascii=False)
    assert len(encoded) <= 1200
    assert json.loads(encoded)["data"]["truncated"] is True
    assert result.data["truncated"] is True and result.data["omitted_count"] > 0
    visible = {f"evt:{item['event_id']}" for item in result.data["items"]}
    assert set(result.evidence_ids) == visible


def test_unexpected_tool_exception_is_logged_but_not_returned_to_model(db_pair, caplog):
    from app.agent.tools import ToolResult
    db, _ = db_pair
    incident = Incident(incident_id="err-i", title="test", status="OPEN", severity="LOW",
        threat_classification="UNKNOWN", overall_risk_score=1, flow_count=0,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    db.add(incident); db.commit()
    registry = ToolRegistry()
    registry.handlers["run_baseline_investigation"] = lambda *args: (_ for _ in ()).throw(
        RuntimeError("provider failed Bearer token123 gsk_secret https://user:pass@host/path"))
    result = registry.run("run_baseline_investigation", {"incident_id": incident.incident_id},
        db, incident, "r", "analyst", set())
    assert result.ok is False and result.error == "tool failed"
    assert "token123" not in result.error and "gsk_secret" not in result.error
    assert "RuntimeError: provider failed Bearer [redacted] [redacted-key] https://[redacted]@host/path" in caplog.text
