from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from app.agent import api
from app.agent.api import ProposalDecisionRequest
from app.agent.models import AgentRun, AgentStep, ActionProposal
from app.agent.proposals import create_pending_proposal
from app.models.entities import Incident, IncidentEvent, SecurityEvent, AnalystAccount


def _analyst(username="peer", role="analyst"):
    return AnalystAccount(account_id=username, username=username, password_hash="x", role=role, is_active=True)


def _scope(db):
    incident = Incident(incident_id="api-i", title="test", status="OPEN", severity="HIGH",
        threat_classification="PortScan", overall_risk_score=80, flow_count=1,
        first_detected_at=datetime.now(timezone.utc), last_updated_at=datetime.now(timezone.utc))
    event = SecurityEvent(event_id="api-e", timestamp=datetime.now(timezone.utc), source_ip="192.0.2.1",
        event_category="network", event_type="flow")
    db.add_all([incident, event]); db.flush()
    db.add(IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id)); db.commit()
    run = AgentRun(run_id="api-run", incident_id=incident.incident_id, requested_by="requester", status="completed",
        agent_id="investigator", mode="agent", model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.flush()
    db.add(AgentStep(id="api-step", run_id=run.run_id, step_no=1, kind="llm", args={}, result_summary="done",
        evidence_ids=[], ok=True, duration_ms=1)); db.commit()
    return incident, ["evt:api-e"]


def _action(incident, evidence):
    return {"action_type": "block_ip", "target_type": "ip", "target": "192.0.2.1",
        "rationale": "Review network evidence.", "confidence": 0.8, "evidence_ids": evidence}


def test_run_list_returns_summaries_without_step_rows(db_pair, monkeypatch):
    db, _ = db_pair
    _scope(db)
    monkeypatch.setattr(api.settings, "AGENT_ENABLED", True)
    monkeypatch.setattr(api, "_reap_stale_runs", lambda: None)
    result = api.list_agent_runs(None, 50, _analyst(), db)
    assert not hasattr(result[0], "steps")
    detail = api._to_response(db.get(AgentRun, "api-run"), db)
    assert len(detail.steps) == 1


def test_pending_proposals_expire_lazily_during_list(db_pair, monkeypatch):
    from app.agent.models import ActionProposal
    db, _ = db_pair
    incident, evidence = _scope(db)
    proposal = create_pending_proposal(db, "api-run", incident, "requester", _action(incident, evidence), set(evidence))
    proposal.created_at = datetime.now(timezone.utc) - timedelta(hours=25)
    db.commit()
    monkeypatch.setattr(api.settings, "AGENT_ENABLED", True)
    monkeypatch.setattr(api, "_reap_stale_runs", lambda: None)
    rows = api.list_agent_proposals("pending", incident.incident_id, _analyst(), db)
    db.refresh(proposal)
    assert rows == [] and proposal.status == "expired"
    with pytest.raises(HTTPException) as exc:
        api.approve_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="late"), _analyst(), db)
    assert exc.value.status_code == 409


@pytest.mark.parametrize("status", ["RESOLVED", "FALSE_POSITIVE"])
def test_terminal_incident_cannot_have_proposal_approved(db_pair, monkeypatch, status):
    db, _ = db_pair
    incident, evidence = _scope(db)
    proposal = create_pending_proposal(db, "api-run", incident, "requester", _action(incident, evidence), set(evidence))
    incident.status = status
    db.commit()
    monkeypatch.setattr(api.settings, "AGENT_ENABLED", True)
    monkeypatch.setattr(api, "_reap_stale_runs", lambda: None)
    with pytest.raises(HTTPException) as exc:
        api.approve_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="review"), _analyst(), db)
    assert exc.value.status_code == 409
    assert db.get(ActionProposal, proposal.proposal_id).status == "pending"
