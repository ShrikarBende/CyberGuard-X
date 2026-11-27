import json
from datetime import datetime, timezone
import pytest
from app.agent.llm import AgentLLM, AssistantTurn, FakeLLM, ToolCall
from app.agent.limits import RunLimits, RunLimitReached
from app.agent.loop import run_agent
from app.agent.manifest import AgentManifest
from app.agent.tools import ToolRegistry, ToolResult, IncidentArgs
from app.models.entities import Incident


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self.payload, self.status_code, self.headers = payload, status_code, headers or {}
    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            request = httpx.Request("POST", "https://offline.invalid")
            response = httpx.Response(self.status_code, request=request, headers=self.headers)
            raise httpx.HTTPStatusError("status", request=request, response=response)
    def json(self): return self.payload


class FakeClient:
    def __init__(self, response): self.response = response
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def post(self, *args, **kwargs): return self.response


def _incident(db):
    row = Incident(incident_id="bound-i", title="test", severity="LOW", status="OPEN",
        threat_classification="UNKNOWN_CANDIDATE", overall_risk_score=2, flow_count=1,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    db.add(row); db.commit()
    return row


class BaselineTool:
    def schemas_for(self, needs): return []
    def run(self, name, args, db, incident, run_id, requested_by, seen_ids):
        return ToolResult({"allowed_chunks": [], "allowed_techniques": []}, [f"inc:{incident.incident_id}"])


def test_native_tool_call_malformed_json_becomes_error_args():
    client_factory = lambda **kwargs: FakeClient(FakeResponse({"choices": [{"message": {
        "content": None, "tool_calls": [{"id": "c1", "function": {"name": "x", "arguments": "{"}}]}}]}))
    turn = AgentLLM("https://offline.invalid", "secret", "fake", client_factory=client_factory).chat([], [])
    assert turn.tool_calls[0].arguments["__malformed_json"] == "{"


def test_native_turn_preserves_provider_message_fields_for_next_tool_round():
    provider_message = {"role": "assistant", "content": None, "reasoning": "metadata",
        "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "run_baseline_investigation", "arguments": "{\"incident_id\":\"i1\"}"}}]}
    client_factory = lambda **kwargs: FakeClient(FakeResponse({"choices": [{"message": provider_message}]}))
    turn = AgentLLM("https://offline.invalid", "secret", "fake", client_factory=client_factory).chat([], [])
    assert turn.provider_message == provider_message


def test_json_action_mode_parses_single_tool_call_without_network():
    client_factory = lambda **kwargs: FakeClient(FakeResponse({"choices": [{"message": {
        "content": '{"tool":"search_knowledge","args":{"query":"MITRE"}}'}}]}))
    llm = AgentLLM("https://offline.invalid", "secret", "fake", mode="json", client_factory=client_factory)
    turn = llm.chat([], [{"function": {"name": "search_knowledge"}}])
    assert turn.tool_calls[0].name == "search_knowledge"
    assert turn.tool_calls[0].arguments == {"query": "MITRE"}


def test_llm_omits_empty_tools_sets_max_tokens_and_omits_empty_key_auth(monkeypatch):
    seen = {}
    class CaptureClient:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def post(self, url, **kwargs):
            seen.update(kwargs)
            return FakeResponse({"choices": [{"message": {"content": "{}"}}]})
    monkeypatch.setattr("app.agent.llm.settings.AGENT_MAX_OUTPUT_TOKENS", 777, raising=False)
    AgentLLM("https://offline.invalid", "", "fake", client_factory=lambda **kwargs: CaptureClient()).chat([], [])
    assert "tools" not in seen["json"] and "tool_choice" not in seen["json"]
    assert seen["json"]["max_tokens"] == 777
    assert "Authorization" not in seen["headers"]


def test_json_mode_sends_schemas_and_converts_tool_history_to_plain_messages():
    seen = {}
    schema = {"type": "function", "function": {"name": "search_knowledge", "parameters": {
        "type": "object", "properties": {"query": {"type": "string"}}}}}
    history = [{"role": "user", "content": "start"},
        {"role": "assistant", "tool_calls": [{"id": "c1", "function": {"name": "search_knowledge",
             "arguments": '{"query":"MITRE"}'}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "search_knowledge", "content": "evidence"}]
    class CaptureClient:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def post(self, url, **kwargs):
            seen.update(kwargs)
            return FakeResponse({"choices": [{"message": {"content": '{"final":{}}'}}]})
    AgentLLM("https://offline.invalid", "secret", "fake", mode="json",
        client_factory=lambda **kwargs: CaptureClient()).chat(history, [schema])
    body = seen["json"]
    assert "tools" not in body and "tool_choice" not in body
    assert all(message["role"] != "tool" and "tool_calls" not in message for message in body["messages"])
    assert '{"tool": "search_knowledge", "args": {"query": "MITRE"}}' in body["messages"][1]["content"]
    assert "untrusted_tool_result" in body["messages"][2]["content"]
    assert "query" in body["messages"][-1]["content"]


def test_native_400_is_remembered_and_retries_json_directly(monkeypatch):
    requests = []
    responses = [FakeResponse({}, 400), FakeResponse({"choices": [{"message": {"content": '{"final":{}}'}}]}),
                 FakeResponse({"choices": [{"message": {"content": '{"final":{}}'}}]})]
    class CaptureClient:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def post(self, url, **kwargs):
            requests.append(kwargs["json"])
            return responses.pop(0)
    llm = AgentLLM("https://offline.invalid", "secret", "fake", client_factory=lambda **kwargs: CaptureClient())
    llm.chat([], [{"type": "function", "function": {"name": "x", "parameters": {}}}])
    assert llm._native_unsupported is True
    llm.chat([], [{"type": "function", "function": {"name": "x", "parameters": {}}}])
    assert len(requests) == 3
    assert "tools" in requests[0] and "tools" not in requests[1] and "tools" not in requests[2]


def test_retry_after_is_honored_for_rate_limit(monkeypatch):
    waits, calls = [], []
    responses = [FakeResponse({}, 429, {"Retry-After": "2"}),
                 FakeResponse({"choices": [{"message": {"content": "{}"}}]})]
    class CaptureClient:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def post(self, url, **kwargs):
            calls.append(kwargs)
            return responses.pop(0)
    monkeypatch.setattr("app.agent.llm.time.sleep", waits.append)
    AgentLLM("https://offline.invalid", "secret", "fake", client_factory=lambda **kwargs: CaptureClient()).chat([], [])
    assert waits == [2]
    assert len(calls) == 2


def test_loop_passes_remaining_wall_budget_as_llm_timeout(db_pair):
    db, _ = db_pair
    incident = _incident(db)
    manifest = AgentManifest(id="test_agent", description="test", needs=["run_baseline_investigation"],
        limits={}, system="safe", conclusion="json")
    llm = FakeLLM([AssistantTurn(content=json.dumps({"summary": "Review needed.",
        "assessment": "unknown_needs_review", "key_findings": [], "attack_mapping": [], "hypotheses": [],
        "missing_evidence": [], "recommended_actions": [], "limitations": []}))])
    run_agent("remaining-timeout", incident.incident_id, "analyst", manifest, llm, ToolRegistry(),
        RunLimits(max_steps=2, max_tool_calls=2, wall_seconds=7, result_chars=1000, max_concurrent_runs=1), db)
    assert llm.calls[0]["timeout"] <= 7


def test_tool_result_cap_includes_evidence_ids(db_pair, monkeypatch):
    db, _ = db_pair
    incident = _incident(db)
    registry = ToolRegistry()
    registry.handlers["run_baseline_investigation"] = lambda *args: ToolResult("x" * 1000, ["evt:e1"] * 30)
    monkeypatch.setattr("app.agent.tools.settings.AGENT_RESULT_CHARS", 256)
    result = registry.run("run_baseline_investigation", {"incident_id": incident.incident_id}, db,
                          incident, "r", "analyst", set())
    encoded = json.dumps({"ok": result.ok, "evidence_ids": result.evidence_ids, "data": result.data})
    assert len(encoded) <= 256
    assert result.data["truncated"] is True


def test_cancel_and_step_limits_are_checked_between_steps(db_pair):
    db, _ = db_pair
    incident = _incident(db)
    manifest = AgentManifest(id="test_agent", description="test", needs=["run_baseline_investigation"],
        limits={}, system="safe", conclusion="json")
    llm = FakeLLM([])
    with pytest.raises(InterruptedError, match="cancelled"):
        run_agent("cancel", incident.incident_id, "analyst", manifest, llm, ToolRegistry(),
            RunLimits(max_steps=2, max_tool_calls=2, wall_seconds=10, result_chars=1000, max_concurrent_runs=1),
            db, cancelled=lambda: True)
    assert not llm.calls
    looping = FakeLLM([AssistantTurn(tool_calls=[ToolCall("run_baseline_investigation", {"incident_id": incident.incident_id})])])
    with pytest.raises(RunLimitReached, match="step limit reached; finalization failed"):
        run_agent("limit", incident.incident_id, "analyst", manifest, looping, BaselineTool(),
            RunLimits(max_steps=1, max_tool_calls=2, wall_seconds=10, result_chars=1000, max_concurrent_runs=1), db)


def test_wall_clock_limit_is_checked_after_llm_returns(db_pair, monkeypatch):
    db, _ = db_pair
    incident = _incident(db)
    manifest = AgentManifest(id="test_agent", description="test", needs=["run_baseline_investigation"], limits={}, system="safe", conclusion="json")
    times = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr("app.agent.loop.time.monotonic", lambda: next(times))
    with pytest.raises(RunLimitReached, match="wall clock"):
        run_agent("wall", incident.incident_id, "analyst", manifest, FakeLLM(["{}"]), ToolRegistry(),
            RunLimits(max_steps=2, max_tool_calls=2, wall_seconds=1, result_chars=1000, max_concurrent_runs=1),
            db, started_monotonic=0.0)
