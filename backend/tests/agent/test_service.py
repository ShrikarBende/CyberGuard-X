from datetime import datetime, timezone
import threading
import pytest
from app.agent import service
from app.agent.llm import AssistantTurn, FakeLLM
from app.agent.models import AgentRun, ActionProposal
from app.agent.limits import RunLimits, RunLimitReached
from app.models.entities import Incident, AnalystActivity, InvestigationNote


def _incident(db, incident_id):
    row = Incident(incident_id=incident_id, title="Test incident", description="", severity="MEDIUM",
        status="OPEN", threat_classification="UNKNOWN_CANDIDATE", overall_risk_score=50,
        flow_count=1, first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    db.add(row); db.commit()
    return row


def test_concurrency_one_run_per_incident_and_cancel_flag(db_pair, monkeypatch):
    db, factory = db_pair
    incidents = [_incident(db, f"i{index}") for index in range(3)]

    class HeldThread:
        def __init__(self, **kwargs): self.kwargs = kwargs; self.started = False
        def start(self): self.started = True
        def is_alive(self): return self.started

    monkeypatch.setattr(service.threading, "Thread", HeldThread)
    monkeypatch.setattr(service.settings, "AGENT_MAX_CONCURRENT_RUNS", 2)
    service._RUNS.clear()
    first = service.start_run(db, incidents[0].incident_id, "requester")
    with pytest.raises(service.RunConflict, match="already active"):
        service.start_run(db, incidents[0].incident_id, "requester")
    second = service.start_run(db, incidents[1].incident_id, "requester")
    with pytest.raises(service.RunConflict, match="Maximum concurrent"):
        service.start_run(db, incidents[2].incident_id, "requester")
    assert service.request_cancel(first.run_id) is True
    assert service.cancel_flag(first.run_id) is True
    assert service.request_cancel("missing") is False
    service._RUNS.clear()


def test_stale_running_rows_are_reaped(db_pair, monkeypatch):
    db, factory = db_pair
    incident = _incident(db, "stale")
    run = AgentRun(run_id="stale-run", incident_id=incident.incident_id, requested_by="analyst", status="running",
        agent_id="investigator", mode="agent", model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    monkeypatch.setattr(service, "SessionLocal", factory)
    service._RUNS.clear()
    service._reap_stale_runs()
    db.expire_all()
    assert db.get(AgentRun, "stale-run").status == "failed"
    assert db.query(AnalystActivity).filter_by(action_type="agent_run_finished").count() == 1


def test_worker_materializes_staged_and_report_actions_once_after_success(db_pair, monkeypatch):
    db, factory = db_pair
    incident = _incident(db, "proposal-success")
    run = AgentRun(run_id="proposal-success-run", incident_id=incident.incident_id,
        requested_by="analyst", status="queued", agent_id="investigator", mode="agent",
        model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    action = {"action_type": "preserve_logs", "target_type": "incident", "target": incident.incident_id,
        "rationale": "Preserve evidence for review.", "confidence": 0.8,
        "evidence_ids": [f"inc:{incident.incident_id}"]}
    monkeypatch.setattr(service, "SessionLocal", factory)
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_URL", "configured")
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_KEY", "configured")
    monkeypatch.setattr(service, "run_agent", lambda *args, **kwargs: {
        "report": {"recommended_actions": [action]}, "validation": {"injection_flags": 0},
        "usage": {}, "staged_actions": [{"action": action}],
        "evidence_ids": [f"inc:{incident.incident_id}"]})
    service._worker(run.run_id, incident.incident_id, "analyst", threading.Event())
    assert db.query(ActionProposal).filter_by(run_id=run.run_id).count() == 1


@pytest.mark.parametrize("outcome", ["injected", "cancelled", "fallback"])
def test_untrusted_or_incomplete_run_never_materializes_staged_actions(db_pair, monkeypatch, outcome):
    db, factory = db_pair
    incident = _incident(db, f"proposal-{outcome}")
    run = AgentRun(run_id=f"proposal-{outcome}-run", incident_id=incident.incident_id,
        requested_by="analyst", status="queued", agent_id="investigator", mode="agent",
        model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    action = {"action_type": "preserve_logs", "target_type": "incident", "target": incident.incident_id,
        "rationale": "Preserve evidence for review.", "confidence": 0.8,
        "evidence_ids": [f"inc:{incident.incident_id}"]}
    monkeypatch.setattr(service, "SessionLocal", factory)
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_URL", "configured")
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_KEY", "configured")
    monkeypatch.setattr(service, "investigate_incident", lambda *args, **kwargs: {"incident_id": incident.incident_id})
    if outcome == "fallback":
        monkeypatch.setattr(service, "_llm_factory", service.AgentLLM)
        monkeypatch.setattr(service.settings, "AGENT_LLM_API_URL", "")
        monkeypatch.setattr(service.settings, "AGENT_LLM_API_KEY", "")
    elif outcome == "cancelled":
        monkeypatch.setattr(service, "run_agent", lambda *args, **kwargs: (_ for _ in ()).throw(InterruptedError("cancelled")))
    else:
        monkeypatch.setattr(service, "run_agent", lambda *args, **kwargs: {
            "report": {"recommended_actions": [action]}, "validation": {"injection_flags": 1},
            "usage": {}, "staged_actions": [{"action": action}],
            "evidence_ids": [f"inc:{incident.incident_id}"]})
    service._worker(run.run_id, incident.incident_id, "analyst", threading.Event())
    assert db.query(ActionProposal).filter_by(run_id=run.run_id).count() == 0
    if outcome == "injected":
        assert db.query(AnalystActivity).filter_by(action_type="agent_proposals_discarded").count() == 1


def test_worker_records_limit_reached_with_deterministic_baseline(db_pair, monkeypatch):
    db, factory = db_pair
    incident = _incident(db, "limit-reached")
    run = AgentRun(run_id="limit-reached-run", incident_id=incident.incident_id, requested_by="analyst",
        status="queued", agent_id="investigator", mode="agent", model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    monkeypatch.setattr(service, "SessionLocal", factory)
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_URL", "configured")
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_KEY", "configured")
    monkeypatch.setattr(service, "investigate_incident", lambda *args, **kwargs: {"incident_id": incident.incident_id})
    monkeypatch.setattr(service, "run_agent", lambda *args, **kwargs: (_ for _ in ()).throw(RunLimitReached("step limit reached")))
    service._worker(run.run_id, incident.incident_id, "analyst", threading.Event())
    db.expire_all()
    saved = db.get(AgentRun, run.run_id)
    assert saved.status == "limit_reached"
    assert saved.validation["fallback_reason"] == "limit_reached: step limit reached"
    assert db.query(ActionProposal).filter_by(run_id=run.run_id).count() == 0


@pytest.mark.parametrize("llm_factory", [None, "exception", "bad_json"])
def test_worker_returns_deterministic_fallback_on_unavailable_or_bad_llm(db_pair, monkeypatch, llm_factory):
    db, factory = db_pair
    incident = _incident(db, f"fallback-{llm_factory}")
    run = AgentRun(run_id=f"run-{llm_factory}", incident_id=incident.incident_id, requested_by="analyst",
        status="queued", agent_id="unknown_hunter", mode="agent", model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    monkeypatch.setattr(service, "SessionLocal", factory)
    monkeypatch.setattr(service, "investigate_incident", lambda *args, **kwargs: {
        "incident_id": incident.incident_id, "read_only": True, "trace": [{"step": "retrieve"}]})
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_URL", "")
    monkeypatch.setattr(service.settings, "AGENT_LLM_API_KEY", "")
    if llm_factory is None:
        monkeypatch.setattr(service, "_llm_factory", service.AgentLLM)
    elif llm_factory == "exception":
        monkeypatch.setattr(service, "_llm_factory", lambda: FakeLLM([RuntimeError("offline")]))
    else:
        monkeypatch.setattr(service, "_llm_factory", lambda: FakeLLM([
            AssistantTurn(content="not json"), AssistantTurn(content="still not json")]))
    service._worker(run.run_id, incident.incident_id, "analyst", threading.Event())
    db.expire_all()
    saved = db.get(AgentRun, run.run_id)
    assert saved.status == "completed_fallback"
    assert saved.mode == "fallback" and saved.report["incident_id"] == incident.incident_id
    assert db.query(InvestigationNote).filter_by(incident_id=incident.incident_id, is_ai_generated=True).count() == 1

