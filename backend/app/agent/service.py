"""Threaded run lifecycle with global and per-incident concurrency guards."""
from datetime import datetime, timezone
import threading
import uuid
from app.agent.config import CEILINGS
from app.agent.limits import clamp_to_ceilings, RunLimits
from app.agent.llm import AgentLLM
from app.agent.loop import run_agent
from app.agent.manifest import load_manifest
from app.agent.models import AgentRun, AgentStep
from app.agent.tools import ToolRegistry
from app.audit import record_analyst_activity
from app.agent.proposals import ProposalRejected, persist_proposal, validate_proposal
from app.core.config import settings
from app.database.session import SessionLocal
from app.models.entities import Incident
from app.rag.assistant import investigate_incident

_RUNS: dict[str, dict] = {}
_RUNS_LOCK = threading.Lock()
_llm_factory = AgentLLM


def _materialize_proposals(db, run, incident, staged, report, evidence_ids, validation):
    if int(validation.get("injection_flags", 0) or 0) > 0:
        if staged or report.get("recommended_actions"):
            record_analyst_activity(db, run.requested_by, "agent_proposals_discarded", "incident",
                incident.incident_id, {"run_id": run.run_id, "reason": "untrusted instruction-like evidence"})
        return
    candidates = [item.get("action", {}) for item in staged]
    candidates.extend(report.get("recommended_actions", []))
    signatures, created = set(), 0
    for action in candidates:
        if created >= 5:
            break
        try:
            normalized = validate_proposal(db, incident, action, set(evidence_ids), signatures, created)
        except ProposalRejected:
            continue
        signature = (normalized["action_type"], normalized["target_type"], normalized["target"].casefold())
        if signature in signatures:
            continue
        persist_proposal(db, run.run_id, incident, run.requested_by, normalized)
        signatures.add(signature)
        created += 1


class RunConflict(RuntimeError):
    pass


def set_llm_factory(factory):
    """Injection point for offline tests; production default uses AgentLLM."""
    global _llm_factory
    _llm_factory = factory


def cancel_flag(run_id):
    with _RUNS_LOCK:
        item = _RUNS.get(run_id)
        return bool(item and item["cancel"].is_set())


def request_cancel(run_id):
    with _RUNS_LOCK:
        item = _RUNS.get(run_id)
        if item is None:
            return False
        item["cancel"].set()
        return True


def _finish(db, run, status, report=None, validation=None, usage=None, error=None):
    run.status = status
    run.finished_at = datetime.now(timezone.utc)
    run.report = report
    run.validation = validation or {}
    run.usage = usage or {}
    run.error = str(error)[:1000] if error else None
    record_analyst_activity(db, run.requested_by, "agent_run_finished", "incident", run.incident_id,
        {"run_id": run.run_id, "status": status, "mode": run.mode})
    db.commit()


def _fallback(db, run, incident, reason=None):
    baseline = investigate_incident(incident, db, top_k=6)
    run.mode = "fallback"
    from app.models.entities import InvestigationNote
    import json
    import uuid
    note = InvestigationNote(note_id=f"agent_note_{uuid.uuid4().hex}", incident_id=incident.incident_id,
        author="cyberguard-agent", content=json.dumps(baseline, ensure_ascii=False, indent=2),
        is_ai_generated=True, citations=[])
    db.add(note)
    _finish(db, run, "completed_fallback", baseline,
            {"fallback_reason": str(reason)[:300] if reason else "LLM is not configured"},
            {"llm_calls": 0, "tool_calls": 0}, None)


def _worker(run_id, incident_id, requested_by, cancel_event):
    with SessionLocal() as db:
        run = db.query(AgentRun).filter(AgentRun.run_id == run_id).first()
        if run is None:
            return
        run.status = "running"
        run.started_at = datetime.now(timezone.utc)
        db.commit()
        incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
        if incident is None:
            _finish(db, run, "failed", error="Incident not found")
            return
        configured = bool(settings.AGENT_LLM_API_URL and settings.AGENT_LLM_API_KEY)
        try:
            if not configured and _llm_factory is AgentLLM:
                _fallback(db, run, incident)
                return
            name = "unknown_hunter" if incident.threat_classification in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"} else "investigator"
            manifest = load_manifest(name)
            limits = clamp_to_ceilings(manifest.limits)
            llm = _llm_factory()
            result = run_agent(run_id, incident_id, requested_by, manifest, llm, ToolRegistry(), limits, db,
                               cancelled=cancel_event.is_set)
            _materialize_proposals(db, run, incident, result.get("staged_actions", []),
                result["report"], result.get("evidence_ids", []), result["validation"])
            _finish(db, run, "completed", result["report"], result["validation"], result["usage"])
        except InterruptedError as exc:
            _finish(db, run, "cancelled", error=exc)
        except Exception as exc:
            # Deterministic fallback protects the analyst from an empty result.
            db.rollback()
            try:
                _fallback(db, run, incident, type(exc).__name__)
            except Exception as fallback_exc:
                _finish(db, run, "failed", error=f"{type(fallback_exc).__name__}: deterministic fallback failed")


def start_run(db, incident_id, requested_by):
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if incident is None:
        raise LookupError("Incident not found")
    configured_limit = min(settings.AGENT_MAX_CONCURRENT_RUNS, CEILINGS["max_concurrent_runs"])
    with _RUNS_LOCK:
        live = {key: value for key, value in _RUNS.items() if value["thread"].is_alive()}
        _RUNS.clear(); _RUNS.update(live)
        if len(_RUNS) >= configured_limit:
            raise RunConflict("Maximum concurrent agent runs reached")
        if any(value["incident_id"] == incident_id for value in _RUNS.values()):
            raise RunConflict("An agent run is already active for this incident")
        run_id = f"agent_{uuid.uuid4().hex}"
        agent_id = "unknown_hunter" if incident.threat_classification in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"} else "investigator"
        run = AgentRun(run_id=run_id, incident_id=incident_id, requested_by=requested_by,
            status="queued", agent_id=agent_id, mode="agent", model_name=settings.AGENT_LLM_MODEL,
            limits=clamp_to_ceilings().as_dict(), usage={}, validation={})
        db.add(run)
        record_analyst_activity(db, requested_by, "agent_run_started", "incident", incident_id,
                                {"run_id": run_id, "agent_id": agent_id})
        db.commit()
        db.refresh(run)
        cancel_event = threading.Event()
        thread = threading.Thread(target=_worker, args=(run_id, incident_id, requested_by, cancel_event),
                                  name=f"agent-{run_id}", daemon=True)
        _RUNS[run_id] = {"thread": thread, "incident_id": incident_id, "cancel": cancel_event}
        thread.start()
        return run


def _reap_stale_runs():
    """Mark persisted runs that lost their worker after a process restart."""
    with _RUNS_LOCK:
        live_ids = {run_id for run_id, value in _RUNS.items() if value["thread"].is_alive()}
    with SessionLocal() as db:
        stale = db.query(AgentRun).filter(AgentRun.status == "running").all()
        for run in stale:
            if run.run_id not in live_ids:
                run.status = "failed"
                run.finished_at = datetime.now(timezone.utc)
                run.error = "interrupted by restart"
                record_analyst_activity(db, run.requested_by, "agent_run_finished", "incident", run.incident_id,
                    {"run_id": run.run_id, "status": "failed", "reason": "interrupted by restart"})
        if stale:
            db.commit()
