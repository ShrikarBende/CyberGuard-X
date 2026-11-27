"""Authenticated API for opt-in investigation runs."""
from datetime import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from app.agent.config import public_config
from app.agent.models import AgentRun, AgentStep, ActionProposal
from app.agent.proposals import decide_proposal, expire_stale_proposals
from app.agent.service import RunConflict, _reap_stale_runs, request_cancel, start_run
from app.auth import get_current_analyst
from app.core.config import settings
from app.database.session import get_db
from app.models.entities import AnalystAccount

router = APIRouter(tags=["Agent Investigation"])


class AgentConfigResponse(BaseModel):
    enabled: bool
    tool_mode: str
    model: str
    limits: dict[str, int]
    execution_mode: str
    max_output_tokens: int
    allow_self_approval: bool


class RunAccepted(BaseModel):
    run_id: str


class AgentStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    run_id: str
    step_no: int
    kind: str
    tool_name: str | None
    args: dict[str, Any]
    result_summary: str
    evidence_ids: list[str]
    ok: bool
    duration_ms: int
    created_at: datetime


class AgentRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    run_id: str
    incident_id: str
    requested_by: str
    status: str
    agent_id: str
    mode: str
    model_name: str
    started_at: datetime | None
    finished_at: datetime | None
    limits: dict[str, Any]
    usage: dict[str, Any]
    report: dict[str, Any] | None
    validation: dict[str, Any]
    error: str | None
    steps: list[AgentStepResponse] = Field(default_factory=list)


class AgentRunSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    run_id: str
    incident_id: str
    requested_by: str
    status: str
    agent_id: str
    mode: str
    model_name: str
    started_at: datetime | None
    finished_at: datetime | None
    limits: dict[str, Any]
    usage: dict[str, Any]
    report: dict[str, Any] | None
    validation: dict[str, Any]
    error: str | None


class ProposalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    proposal_id: str
    run_id: str
    incident_id: str
    action_type: str
    target_type: str
    target: str
    rationale: str
    confidence: float
    evidence_ids: list[str]
    status: str
    requested_by: str
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    execution_state: str | None
    created_at: datetime


class ProposalDecisionRequest(BaseModel):
    note: str = Field(default="", max_length=1000)


def _require_enabled():
    if not settings.AGENT_ENABLED:
        raise HTTPException(status_code=503, detail="Agent layer disabled")


def _require_role(analyst, roles):
    if analyst.role not in roles:
        raise HTTPException(status_code=403, detail="Your analyst role cannot perform this action.")


def require_agent_analyst(analyst: AnalystAccount = Depends(get_current_analyst)):
    # Keep the disabled response uniform, then enforce the role before the handler runs.
    _require_enabled()
    _require_role(analyst, {"analyst", "admin"})
    return analyst


require_agent_analyst.required_roles = frozenset({"analyst", "admin"})


def _to_response(run, db):
    steps = db.query(AgentStep).filter(AgentStep.run_id == run.run_id).order_by(
        AgentStep.step_no.asc(), AgentStep.created_at.asc()).all()
    return AgentRunResponse.model_validate({**{key: getattr(run, key) for key in (
        "run_id", "incident_id", "requested_by", "status", "agent_id", "mode", "model_name",
        "started_at", "finished_at", "limits", "usage", "report", "validation", "error")},
        "steps": steps})


@router.get("/api/agent/config", response_model=AgentConfigResponse)
def get_agent_config(_analyst: AnalystAccount = Depends(get_current_analyst)):
    return public_config()


@router.post("/api/incidents/{incident_id}/agent-investigate", response_model=RunAccepted,
             status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_agent_analyst)])
def start_agent_investigation(incident_id: str, analyst: AnalystAccount = Depends(get_current_analyst),
                              db: Session = Depends(get_db)):
    _require_enabled()
    _reap_stale_runs()
    try:
        run = start_run(db, incident_id, analyst.username)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RunConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"run_id": run.run_id}


@router.get("/api/agent/runs", response_model=list[AgentRunSummary])
def list_agent_runs(incident_id: str | None = None, limit: int = Query(50, ge=1, le=200),
                    _analyst: AnalystAccount = Depends(get_current_analyst), db: Session = Depends(get_db)):
    _require_enabled()
    query = db.query(AgentRun)
    if incident_id:
        query = query.filter(AgentRun.incident_id == incident_id)
    runs = query.order_by(AgentRun.started_at.desc().nullslast()).limit(limit).all()
    return [AgentRunSummary.model_validate(run) for run in runs]


@router.get("/api/agent/runs/{run_id}", response_model=AgentRunResponse)
def get_agent_run(run_id: str, _analyst: AnalystAccount = Depends(get_current_analyst),
                  db: Session = Depends(get_db)):
    _require_enabled(); _reap_stale_runs()
    run = db.query(AgentRun).filter(AgentRun.run_id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return _to_response(run, db)


@router.post("/api/agent/runs/{run_id}/cancel", response_model=AgentRunResponse,
             dependencies=[Depends(require_agent_analyst)])
def cancel_agent_run(run_id: str, _analyst: AnalystAccount = Depends(get_current_analyst),
                     db: Session = Depends(get_db)):
    _require_enabled()
    run = db.query(AgentRun).filter(AgentRun.run_id == run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Agent run not found")
    if run.status in {"queued", "running"}:
        if not request_cancel(run_id):
            raise HTTPException(status_code=409, detail="Run is no longer active")
    return _to_response(run, db)


@router.get("/api/agent/proposals", response_model=list[ProposalResponse])
def list_agent_proposals(status_filter: str | None = Query(None, alias="status"),
                         incident_id: str | None = None,
                         _analyst: AnalystAccount = Depends(get_current_analyst),
                         db: Session = Depends(get_db)):
    _require_enabled()
    expire_stale_proposals(db)
    query = db.query(ActionProposal)
    if status_filter:
        if status_filter not in {"pending", "approved", "rejected", "expired"}:
            raise HTTPException(status_code=422, detail="Invalid proposal status")
        query = query.filter(ActionProposal.status == status_filter)
    if incident_id:
        query = query.filter(ActionProposal.incident_id == incident_id)
    return query.order_by(ActionProposal.created_at.desc()).limit(200).all()


def _decide(proposal_id, body, analyst, db, decision):
    _require_enabled()
    proposal = db.query(ActionProposal).filter(ActionProposal.proposal_id == proposal_id).first()
    if proposal is None:
        raise HTTPException(status_code=404, detail="Action proposal not found")
    try:
        return decide_proposal(db, proposal, analyst, decision, body.note)
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/api/agent/proposals/{proposal_id}/approve", response_model=ProposalResponse,
             dependencies=[Depends(require_agent_analyst)])
def approve_agent_proposal(proposal_id: str, body: ProposalDecisionRequest,
                           analyst: AnalystAccount = Depends(get_current_analyst), db: Session = Depends(get_db)):
    return _decide(proposal_id, body, analyst, db, "approved")


@router.post("/api/agent/proposals/{proposal_id}/reject", response_model=ProposalResponse,
             dependencies=[Depends(require_agent_analyst)])
def reject_agent_proposal(proposal_id: str, body: ProposalDecisionRequest,
                          analyst: AnalystAccount = Depends(get_current_analyst), db: Session = Depends(get_db)):
    return _decide(proposal_id, body, analyst, db, "rejected")
