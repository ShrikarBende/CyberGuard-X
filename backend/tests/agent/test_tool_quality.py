from datetime import datetime, timezone
from app.agent.tools import ARG_MODELS, ToolRegistry
from app.models.entities import Incident


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
