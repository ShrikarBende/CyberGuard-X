"""Create pending-only proposals; human decision handling is added in P2."""
from datetime import datetime, timezone
import ipaddress
import uuid
from sqlalchemy import func
from app.audit import record_analyst_activity
from app.agent.models import ActionProposal
from app.models.entities import IncidentEvent, SecurityEvent, User, Device

ACTION_TYPES = {"preserve_logs", "monitor", "escalate", "block_ip", "reset_credentials",
                "disable_account", "isolate_host"}


class ProposalRejected(ValueError):
    pass


def _reject(db, requested_by, incident, action, reason):
    record_analyst_activity(db, requested_by, "agent_proposal_rejected", "incident",
                            incident.incident_id, {"action_type": action.get("action_type"), "reason": reason[:300]})
    db.commit()
    raise ProposalRejected(reason)


def validate_proposal(db, incident, action, seen_ids, signatures=(), count=0):
    kind = str(action.get("action_type", ""))
    target_type = str(action.get("target_type", ""))
    target = str(action.get("target", ""))
    rationale = str(action.get("rationale", ""))[:1200]
    try:
        confidence = float(action.get("confidence"))
    except (TypeError, ValueError):
        confidence = 0.0
    evidence_ids = [str(x) for x in action.get("evidence_ids", []) if str(x) in seen_ids]
    if kind not in ACTION_TYPES:
        raise ProposalRejected("unsupported action type")
    if not target or not rationale or not 0 < confidence <= 1 or not evidence_ids:
        raise ProposalRejected("target, rationale, valid evidence, and confidence in (0,1] are required")
    signature = (kind, target_type, target.casefold())
    if signature in signatures:
        raise ProposalRejected("duplicate proposal")
    if count >= 5:
        raise ProposalRejected("maximum of five proposals per run reached")

    if kind in {"preserve_logs", "monitor", "escalate"}:
        if target_type != "incident" or target != incident.incident_id:
            raise ProposalRejected("this action must target the incident id")
    else:
        incident_event_ids = [row.event_id for row in db.query(IncidentEvent.event_id).filter(
            IncidentEvent.incident_id == incident.incident_id).all()]
        events = db.query(SecurityEvent).filter(SecurityEvent.event_id.in_(incident_event_ids)).all() if incident_event_ids else []
        scoped_events = {e.event_id for e in events}
        if kind == "block_ip":
            try:
                ipaddress.ip_address(target)
            except ValueError:
                raise ProposalRejected("block_ip target must be a valid IP address")
            observed = {value for event in events for value in (event.source_ip, event.destination_ip) if value}
            if target_type != "ip" or target not in observed or not any(f"evt:{eid}" in seen_ids for eid in scoped_events):
                raise ProposalRejected("block_ip target must be an IP present in run evidence")
        elif kind in {"disable_account", "reset_credentials"}:
            user = db.query(User).filter(User.user_id == incident.user_id).first() if incident.user_id else None
            observed_users = {e.user_id for e in events if f"evt:{e.event_id}" in seen_ids and e.user_id}
            user_ids = observed_users | ({incident.user_id} if incident.user_id else set())
            users = db.query(User).filter(User.user_id.in_(user_ids)).all() if user_ids else []
            candidates = {value for row in users for value in (row.user_id, row.username)}
            candidates.update(user_ids)
            if target_type != "user" or target not in candidates:
                raise ProposalRejected("account target must be incident user or user in run evidence")
        elif kind == "isolate_host":
            device_ids = {e.device_id for e in events if f"evt:{e.event_id}" in seen_ids and e.device_id}
            if incident.device_id:
                device_ids.add(incident.device_id)
            devices = db.query(Device).filter(Device.device_id.in_(device_ids)).all() if device_ids else []
            candidates = {value for row in devices for value in (row.device_id, row.hostname)}
            candidates.update(device_ids)
            if target_type not in {"host", "device"} or target not in candidates:
                raise ProposalRejected("host target must be incident device or host in run evidence")

    return {"action_type": kind, "target_type": target_type, "target": target,
        "rationale": rationale, "confidence": confidence, "evidence_ids": evidence_ids}


def persist_proposal(db, run_id, incident, requested_by, action):
    kind = action["action_type"]
    target_type = action["target_type"]
    target = action["target"]
    rationale = action["rationale"]
    confidence = action["confidence"]
    evidence_ids = action["evidence_ids"]
    proposal = ActionProposal(proposal_id=f"proposal_{uuid.uuid4().hex}", run_id=run_id,
        incident_id=incident.incident_id, action_type=kind, target_type=target_type, target=target,
        rationale=rationale, confidence=confidence, evidence_ids=evidence_ids, status="pending",
        requested_by=requested_by, execution_state=None)
    db.add(proposal)
    record_analyst_activity(db, requested_by, "agent_action_proposed", "incident", incident.incident_id,
        {"proposal_id": proposal.proposal_id, "action_type": kind, "target_type": target_type,
         "target": target, "evidence_ids": evidence_ids})
    db.flush()
    return proposal


def create_pending_proposal(db, run_id, incident, requested_by, action, seen_ids):
    existing = db.query(ActionProposal).filter(ActionProposal.run_id == run_id).all()
    signatures = {(row.action_type, row.target_type, row.target.casefold()) for row in existing}
    try:
        validated = validate_proposal(db, incident, action, seen_ids, signatures, len(existing))
    except ProposalRejected as exc:
        _reject(db, requested_by, incident, action, str(exc))
    proposal = persist_proposal(db, run_id, incident, requested_by, validated)
    db.commit()
    db.refresh(proposal)
    return proposal


def simulate_execute(db, proposal, decided_by):
    """Record dry-run approval only; this function never invokes a response system."""
    proposal.execution_state = "simulated"
    record_analyst_activity(db, decided_by, "agent_action_simulated", "incident", proposal.incident_id,
        {"proposal_id": proposal.proposal_id, "action_type": proposal.action_type,
         "target_type": proposal.target_type, "target": proposal.target, "mode": "dry_run"})
    db.flush()


def decide_proposal(db, proposal, analyst, decision, note=""):
    if decision not in {"approved", "rejected"}:
        raise ValueError("Unsupported proposal decision")
    if proposal.status != "pending":
        raise ValueError("Only pending proposals can be decided")
    if analyst.role == "viewer":
        raise PermissionError("Viewers cannot decide proposals")
    if analyst.role != "admin" and analyst.username == proposal.requested_by:
        raise PermissionError("Four-eyes approval requires a different analyst")
    proposal.status = decision
    proposal.decided_by = analyst.username
    proposal.decided_at = datetime.now(timezone.utc)
    proposal.decision_note = (note or "")[:1000]
    record_analyst_activity(db, analyst.username, f"agent_proposal_{decision}", "incident",
        proposal.incident_id, {"proposal_id": proposal.proposal_id, "requested_by": proposal.requested_by,
                               "note": proposal.decision_note})
    if decision == "approved":
        simulate_execute(db, proposal, analyst.username)
    db.commit()
    db.refresh(proposal)
    return proposal
