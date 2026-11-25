from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from app.agent.api import (ProposalDecisionRequest, approve_agent_proposal, reject_agent_proposal,
                           list_agent_proposals)
from app.agent.models import ActionProposal, AgentRun
from app.agent.proposals import create_pending_proposal
from app.models.entities import (Incident, IncidentEvent, SecurityEvent, User, Device,
                                 AnalystAccount, AnalystActivity)


def _scope(db, n=2):
    user = User(user_id="u1", username="analyst-target")
    device = Device(device_id="d1", hostname="host-1")
    incident = Incident(incident_id="ip1", title="Test", severity="HIGH", status="OPEN",
        threat_classification="PortScan", overall_risk_score=90, user_id=user.user_id,
        device_id=device.device_id, flow_count=1, first_detected_at=datetime.now(timezone.utc),
        last_updated_at=datetime.now(timezone.utc))
    db.add_all([user, device, incident]); db.flush()
    event_ids = []
    for index in range(n):
        event = SecurityEvent(event_id=f"e{index}", timestamp=datetime.now(timezone.utc),
            user_id=user.user_id, device_id=device.device_id, source_ip=f"192.0.2.{index + 1}",
            destination_ip="198.51.100.1", event_category="network", event_type="flow")
        db.add(event); db.flush()
        db.add(IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id))
        event_ids.append(event.event_id)
    run = AgentRun(run_id="run-proposals", incident_id=incident.incident_id, requested_by="requester",
        status="running", agent_id="investigator", mode="agent", model_name="fake", limits={}, usage={}, validation={})
    db.add(run); db.commit()
    return incident, event_ids


def _action(kind="block_ip", target="192.0.2.1", target_type="ip", evidence=None, confidence=0.7):
    return {"action_type": kind, "target_type": target_type, "target": target,
        "rationale": "Preserve evidence for analyst review.", "confidence": confidence,
        "evidence_ids": evidence or ["evt:e0"]}


def _analyst(username, role="analyst"):
    return AnalystAccount(account_id=username, username=username, password_hash="x", role=role, is_active=True)


def test_proposal_validates_action_targets_confidence_and_run_evidence(db_pair):
    db, _ = db_pair
    incident, events = _scope(db)
    valid = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action(evidence=[f"evt:{events[0]}"]), {f"evt:{events[0]}", f"inc:{incident.incident_id}"})
    assert valid.status == "pending"
    assert valid.execution_state is None
    with pytest.raises(ValueError, match="valid IP"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action(target="not-an-ip", evidence=[f"evt:{events[0]}"]), {f"evt:{events[0]}"})
    with pytest.raises(ValueError, match="present in run evidence"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action(target="203.0.113.99", evidence=[f"evt:{events[0]}"]), {f"evt:{events[0]}"})
    with pytest.raises(ValueError, match="confidence"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action(confidence=0, evidence=[f"evt:{events[1]}"]), {f"evt:{events[1]}"})
    with pytest.raises(ValueError, match="valid evidence"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action(evidence=["evt:fake"]), {f"evt:{events[1]}"})


def test_proposal_scope_types_four_eyes_and_maximum(db_pair):
    db, _ = db_pair
    incident, event_ids = _scope(db, n=6)
    seen = {f"evt:{event_id}" for event_id in event_ids} | {f"inc:{incident.incident_id}"}
    user_proposal = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action("disable_account", "u1", "user", [f"evt:{event_ids[0]}"]), seen)
    host_proposal = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action("isolate_host", "host-1", "host", [f"evt:{event_ids[0]}"]), seen)
    assert user_proposal.status == host_proposal.status == "pending"
    created = [user_proposal, host_proposal]
    for index in range(3):
        ip = f"192.0.2.{index + 1}"
        created.append(create_pending_proposal(db, "run-proposals", incident, "requester",
            _action("block_ip", ip, "ip", [f"evt:{event_ids[index]}"]), seen))
    assert db.query(ActionProposal).filter_by(run_id="run-proposals").count() == 5
    with pytest.raises(ValueError, match="maximum of five"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action("block_ip", "192.0.2.4", "ip", [f"evt:{event_ids[3]}"], confidence=0.6), seen)
    with pytest.raises(ValueError, match="duplicate"):
        create_pending_proposal(db, "run-proposals", incident, "requester",
            _action("block_ip", "192.0.2.1", "ip", [f"evt:{event_ids[0]}"], confidence=0.6), seen)


def test_approval_four_eyes_viewer_reject_and_simulation_audit(db_pair, monkeypatch):
    from app.agent import api
    monkeypatch.setattr(api.settings, "AGENT_ENABLED", True)
    monkeypatch.setattr(api, "_reap_stale_runs", lambda: None)
    db, _ = db_pair
    incident, event_ids = _scope(db)
    proposal = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action(evidence=[f"evt:{event_ids[0]}"], target="192.0.2.1"),
        {f"evt:{event_ids[0]}", f"inc:{incident.incident_id}"})
    visible = list_agent_proposals("pending", incident.incident_id, _analyst("viewer", "viewer"), db)
    assert [row.proposal_id for row in visible] == [proposal.proposal_id]
    with pytest.raises(HTTPException) as requester_error:
        approve_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="self"), _analyst("requester"), db)
    assert requester_error.value.status_code == 403 and "Four-eyes" in requester_error.value.detail
    with pytest.raises(HTTPException) as viewer_error:
        reject_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="no"), _analyst("read-only", "viewer"), db)
    assert viewer_error.value.status_code == 403
    approved = approve_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="Reviewed"), _analyst("peer"), db)
    assert approved.status == "approved" and approved.decided_by == "peer"
    assert approved.execution_state == "simulated"
    assert db.get(Device, "d1").is_isolated is False
    rejected_proposal = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action(evidence=[f"evt:{event_ids[1]}"], target="192.0.2.2"), {f"evt:{event_ids[1]}"})
    rejected = reject_agent_proposal(rejected_proposal.proposal_id, ProposalDecisionRequest(note="Insufficient evidence"),
                                     _analyst("peer"), db)
    assert rejected.status == "rejected" and rejected.execution_state is None
    audits = {row.action_type for row in db.query(AnalystActivity).all()}
    assert {"agent_action_proposed", "agent_proposal_approved", "agent_proposal_rejected",
            "agent_action_simulated"}.issubset(audits)
    with pytest.raises(HTTPException) as duplicate_decision:
        reject_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="again"), _analyst("peer2"), db)
    assert duplicate_decision.value.status_code == 409


def test_admin_can_approve_own_proposal(db_pair, monkeypatch):
    from app.agent import api
    monkeypatch.setattr(api.settings, "AGENT_ENABLED", True)
    monkeypatch.setattr(api, "_reap_stale_runs", lambda: None)
    db, _ = db_pair
    incident, event_ids = _scope(db)
    proposal = create_pending_proposal(db, "run-proposals", incident, "requester",
        _action(evidence=[f"evt:{event_ids[0]}"], target="192.0.2.1"), {f"evt:{event_ids[0]}"})
    approved = approve_agent_proposal(proposal.proposal_id, ProposalDecisionRequest(note="admin review"),
        _analyst("requester", "admin"), db)
    assert approved.execution_state == "simulated"
