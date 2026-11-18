"""
REST API Endpoints for Enterprise CyberGuard X.
Implements Section 16 endpoints:
- POST /api/upload
- POST /api/analyze
- GET /api/events
- GET /api/alerts
- GET /api/incidents
- GET /api/incidents/{id}
- GET /api/dashboard/stats
- GET /api/threats
- GET /api/explainability/{id}
- POST /api/rag/chat
- POST /api/models/retrain
- GET /api/models/status
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
import uuid
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
import threading

_EVALUATION_JOBS = {}
_EVALUATION_JOBS_LOCK = threading.Lock()
_UPLOAD_JOBS = {}
_UPLOAD_JOBS_LOCK = threading.Lock()
_REPLAY_JOB = {"status": "idle", "job_id": None, "processed": 0, "total": 0, "error": None}
_REPLAY_STOP = threading.Event()
_REPLAY_LOCK = threading.Lock()
_RETRAIN_JOBS = {}
_RETRAIN_JOBS_LOCK = threading.Lock()
_SHAP_CACHE = {}
logger = logging.getLogger(__name__)

from app.database.session import get_db
from app.database.session import SessionLocal
from app.audit import record_analyst_activity
from app.auth import get_current_analyst, require_roles
from app.models.entities import (
    User,
    Device,
    SecurityEvent,
    DetectionResult,
    Incident,
    IncidentEvent,
    RiskScore,
    InvestigationNote,
    MitreTechnique,
    AnalystActivity,
    AnalystAccount,
)
from app.schemas.schemas import (
    SecurityEventCreate,
    SecurityEventResponse,
    DetectionResultResponse,
    IncidentResponse,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
    DashboardStatsResponse,
    RAGChatRequest,
    RAGChatResponse,
)
from app.services.websocket_manager import ws_manager

router = APIRouter(
    prefix="/api", tags=["CyberGuard X Core API"],
    dependencies=[Depends(get_current_analyst)],
)


class DemoReplayRequest(BaseModel):
    n: int = Field(default=3000, ge=1, le=100000)
    speed: float = Field(default=10.0, ge=0.0, le=10000.0, description="Rows per second; 0 is unthrottled")


class RetrainRequest(BaseModel):
    profile: str = Field(pattern="^(light|medium)$")


# -------------------------------------------------------------------
# 1. Dashboard Statistics (/api/dashboard/stats)
# -------------------------------------------------------------------
@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return executive overview statistics and charts."""
    total_events = db.query(func.count(SecurityEvent.event_id)).scalar() or 0
    total_detections = db.query(func.count(DetectionResult.detection_id)).scalar() or 0
    total_threats = db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.verdict == "KNOWN_THREAT").scalar() or 0
    known_threats = db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.verdict == "KNOWN_THREAT").scalar() or 0
    unknown_candidates = db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.verdict == "UNKNOWN_CANDIDATE").scalar() or 0
    critical_incidents = db.query(func.count(Incident.incident_id)).filter(Incident.severity == "CRITICAL").scalar() or 0
    normal_events = db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.verdict == "BENIGN").scalar() or 0

    # Tactic distribution is based only on stored MITRE mappings.
    mitre_counts = db.query(MitreTechnique.tactic, func.count(MitreTechnique.id)).group_by(MitreTechnique.tactic).all()
    if mitre_counts:
        threat_distribution = [{"name": tactic, "value": count} for tactic, count in mitre_counts]
    else:
        threat_distribution = []

    # Risk trend over last 60 minutes
    now = datetime.now(timezone.utc)
    risk_trend = [
        {"time": incident.first_detected_at.strftime("%H:%M"), "risk": incident.overall_risk_score}
        for incident in db.query(Incident)
        .filter(Incident.first_detected_at >= now - timedelta(minutes=60))
        .order_by(Incident.first_detected_at)
        .all()
    ]

    # Layer detection stats
    layer_stats = {
        "user_identity": db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.layer == "user").scalar() or 0,
        "endpoint_device": db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.layer == "endpoint").scalar() or 0,
        "network_traffic": db.query(func.count(DetectionResult.detection_id)).filter(DetectionResult.layer == "network").scalar() or 0,
    }

    return DashboardStatsResponse(
        total_events=total_events,
        total_detections=total_detections,
        total_threats=total_threats,
        known_threats=known_threats,
        unknown_candidates=unknown_candidates,
        critical_incidents=critical_incidents,
        normal_events=normal_events,
        threat_distribution=threat_distribution,
        risk_trend=risk_trend,
        layer_detection_stats=layer_stats,
        system_status="operational"
    )


# -------------------------------------------------------------------
# 2. Events (/api/events)
# -------------------------------------------------------------------
@router.get("/events", response_model=List[SecurityEventResponse])
def get_security_events(
    category: Optional[str] = Query(None, description="auth, endpoint, network, access"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieve normalized security events."""
    query = db.query(SecurityEvent)
    if category:
        query = query.filter(SecurityEvent.event_category == category)
    return query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()


@router.get("/demo/status")
def get_demo_status(db: Session = Depends(get_db)):
    """Report whether synthetic demo telemetry exists for the global UI banner."""
    has_demo = db.query(SecurityEvent.event_id).filter(
        SecurityEvent.dataset == "synthetic_demo"
    ).first() is not None
    return {"has_synthetic_demo": has_demo}


@router.post("/demo/load")
def load_demo_scenarios(
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("admin")),
):
    """Insert labelled demo telemetry only; correlation is a separate action."""
    from app.ingestion.scenarios import generate_demo_events

    events = generate_demo_events()
    existing_count = db.query(func.count(SecurityEvent.event_id)).filter(
        SecurityEvent.dataset == "synthetic_demo"
    ).scalar() or 0
    if existing_count:
        record_analyst_activity(
            db, analyst.username, "demo_load", "dataset", "synthetic_demo",
            {"status": "already_loaded", "events": existing_count},
        )
        db.commit()
        return {"status": "already_loaded", "events": existing_count}

    user_ids = {event["user_id"] for event in events if event.get("user_id")}
    device_ids = {event["device_id"] for event in events if event.get("device_id")}
    existing_user_ids = set()
    if user_ids:
        existing_user_ids = {
            row[0] for row in db.query(User.user_id).filter(User.user_id.in_(user_ids)).all()
        }
    existing_device_ids = set()
    if device_ids:
        existing_device_ids = {
            row[0] for row in db.query(Device.device_id).filter(Device.device_id.in_(device_ids)).all()
        }
    for user_id in sorted(user_ids - existing_user_ids):
        db.add(User(user_id=user_id, username=user_id, role="demo", privilege_level="standard"))
    for device_id in sorted(device_ids - existing_device_ids):
        db.add(Device(device_id=device_id, hostname=device_id, os="Synthetic demo", device_type="workstation"))
    for event_data in events:
        db.add(SecurityEvent(**event_data))
    record_analyst_activity(
        db, analyst.username, "demo_load", "dataset", "synthetic_demo",
        {"status": "loaded", "events": len(events)},
    )
    db.commit()
    return {
        "status": "loaded",
        "dataset": "synthetic_demo",
        "events_inserted": len(events),
        "scenarios": sorted({event["scenario"] for event in events}),
        "message": "Synthetic demo events inserted. No detections, incidents, risk scores, or MITRE rows were created.",
    }


@router.delete("/demo/events")
def delete_demo_events(
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("admin")),
):
    """Remove labelled demo events and only their unreferenced demo entities."""
    event_ids = [row[0] for row in db.query(SecurityEvent.event_id).filter(
        SecurityEvent.dataset == "synthetic_demo"
    ).all()]
    events_deleted = 0
    detections_deleted = 0
    associations_deleted = 0
    if event_ids:
        detections_deleted = db.query(DetectionResult).filter(
            DetectionResult.event_id.in_(event_ids)
        ).delete(synchronize_session=False)
        associations_deleted = db.query(IncidentEvent).filter(
            IncidentEvent.event_id.in_(event_ids)
        ).delete(synchronize_session=False)
        events_deleted = db.query(SecurityEvent).filter(
            SecurityEvent.event_id.in_(event_ids)
        ).delete(synchronize_session=False)

    users_deleted = 0
    for user in db.query(User).filter(User.role == "demo").all():
        has_other_events = db.query(SecurityEvent.event_id).filter(
            SecurityEvent.user_id == user.user_id
        ).first() is not None
        has_incident_reference = db.query(Incident.incident_id).filter(
            Incident.user_id == user.user_id
        ).first() is not None
        if not has_other_events and not has_incident_reference:
            db.delete(user)
            users_deleted += 1

    devices_deleted = 0
    for device in db.query(Device).filter(Device.os == "Synthetic demo").all():
        has_other_events = db.query(SecurityEvent.event_id).filter(
            SecurityEvent.device_id == device.device_id
        ).first() is not None
        has_incident_reference = db.query(Incident.incident_id).filter(
            Incident.device_id == device.device_id
        ).first() is not None
        if not has_other_events and not has_incident_reference:
            db.delete(device)
            devices_deleted += 1

    record_analyst_activity(
        db, analyst.username, "demo_reset", "dataset", "synthetic_demo",
        {
            "events_deleted": events_deleted,
            "detections_deleted": detections_deleted,
            "incident_event_links_deleted": associations_deleted,
            "users_deleted": users_deleted,
            "devices_deleted": devices_deleted,
        },
    )
    db.commit()
    return {
        "status": "deleted",
        "events": events_deleted,
        "users": users_deleted,
        "devices": devices_deleted,
    }


@router.post("/demo/replay")
async def start_demo_replay(
    request: DemoReplayRequest,
    analyst: AnalystAccount = Depends(require_roles("admin")),
):
    """Replay the prepared held-out sample through the in-process live engine."""
    from app.core.config import BACKEND_DIR
    from app.detection.engine import load_model_bundle

    sample_path = BACKEND_DIR / "datasets" / "replay" / "replay_sample.csv.gz"
    if not sample_path.is_file():
        raise HTTPException(status_code=404, detail=f"Replay sample not found: {sample_path}. Generate it with backend/ml/training/make_replay_sample.py.")
    try:
        load_model_bundle()
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    with _REPLAY_LOCK:
        if _REPLAY_JOB.get("status") in {"queued", "running", "stopping"}:
            raise HTTPException(status_code=409, detail="A replay is already running.")
        job_id = uuid.uuid4().hex
        _REPLAY_STOP.clear()
        _REPLAY_JOB.update(status="queued", job_id=job_id, processed=0, total=request.n, error=None)

    async def run_replay():
        import pandas as pd
        from app.schemas.schemas import SecurityEventCreate
        from app.detection.engine import process_single_event

        try:
            rows = pd.read_csv(sample_path, compression="gzip", nrows=request.n)
            bundle = load_model_bundle()
            feature_names = list(bundle["feature_names"])
            missing = [name for name in feature_names if name not in rows.columns]
            if missing:
                raise ValueError(f"Replay sample is missing model features: {missing[:5]}")
            with SessionLocal() as replay_db:
                with _REPLAY_LOCK:
                    _REPLAY_JOB["status"] = "running"
                    _REPLAY_JOB["total"] = len(rows)
                for row_index, (_, row) in enumerate(rows.iterrows(), start=1):
                    if _REPLAY_STOP.is_set():
                        break
                    values = {name: float(row[name]) for name in feature_names}
                    timestamp = None
                    if "Timestamp" in rows.columns and pd.notna(row["Timestamp"]):
                        timestamp = pd.to_datetime(row["Timestamp"], utc=True, errors="coerce")
                        timestamp = timestamp.to_pydatetime() if not pd.isna(timestamp) else None
                    payload = {"cicids_features": values}
                    family = row.get("family")
                    if family is not None and not pd.isna(family):
                        payload["family_label"] = str(family)
                    event_values = dict(
                        event_type="cicids2017_flow",
                        event_category="network",
                        dataset="cicids2017_replay",
                        raw_payload=payload,
                    )
                    if timestamp is not None:
                        event_values["timestamp"] = timestamp
                    event = SecurityEventCreate(**event_values)
                    await process_single_event(event, replay_db)
                    with _REPLAY_LOCK:
                        _REPLAY_JOB["processed"] = row_index
                    if request.speed > 0 and row_index < len(rows):
                        await asyncio.sleep(1.0 / request.speed)
            with _REPLAY_LOCK:
                _REPLAY_JOB["status"] = "stopped" if _REPLAY_STOP.is_set() else "completed"
        except Exception as exc:
            logger.exception("Demo replay failed")
            with _REPLAY_LOCK:
                _REPLAY_JOB.update(status="failed", error=str(exc))

    import asyncio
    asyncio.create_task(run_replay(), name=f"replay-{job_id[:8]}")
    return {"status": "queued", "job_id": job_id, "n": request.n, "speed": request.speed}


@router.get("/demo/replay/status")
def get_demo_replay_status():
    with _REPLAY_LOCK:
        return dict(_REPLAY_JOB)


@router.post("/demo/replay/stop")
def stop_demo_replay(analyst: AnalystAccount = Depends(require_roles("admin"))):
    with _REPLAY_LOCK:
        if _REPLAY_JOB.get("status") in {"queued", "running"}:
            _REPLAY_JOB["status"] = "stopping"
            _REPLAY_STOP.set()
        return dict(_REPLAY_JOB)


@router.post("/correlation/run")
def run_rule_correlation(
    window_minutes: int = Query(60, ge=1, le=1440),
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("admin")),
):
    """Evaluate rule indicators and persist only qualifying correlated incidents."""
    from app.correlation.engine import run_correlation

    result = run_correlation(db, window_minutes)
    result["incidents"] = [IncidentResponse.model_validate(incident).model_dump(mode="json")
                           for incident in result["incidents"]]
    return result


# -------------------------------------------------------------------
# 3. Alerts & Threats (/api/alerts, /api/threats)
# -------------------------------------------------------------------
@router.get("/alerts", response_model=List[DetectionResultResponse])
def get_alerts(
    verdict: Optional[str] = Query(None, description="BENIGN, KNOWN_THREAT, UNKNOWN_CANDIDATE"),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieve detection alerts."""
    query = db.query(DetectionResult)
    if verdict:
        query = query.filter(DetectionResult.verdict == verdict)
    else:
        query = query.filter(DetectionResult.verdict != "BENIGN")
    return query.order_by(desc(DetectionResult.created_at)).limit(limit).all()


@router.get("/threats")
def get_threat_intelligence(db: Session = Depends(get_db)):
    """Return categorized threat intelligence summary."""
    detections = db.query(DetectionResult).all()
    detection_count = len(detections)
    known = [d for d in detections if d.verdict == "KNOWN_THREAT"]
    candidates = [d for d in detections if d.verdict == "UNKNOWN_CANDIDATE"]

    return {
        "detection_count": detection_count,
        "summary": {
            "total_detections": detection_count,
            "known_threats_count": len(known),
            "unknown_candidates_count": len(candidates),
            "candidate_rate": round(len(candidates) / detection_count, 3) if detection_count else 0.0
        },
        "known_categories": list({d.predicted_class for d in known if d.predicted_class}),
        "unknown_candidates": [
            {
                "detection_id": d.detection_id,
                "event_id": d.event_id,
                "attack_probability": d.attack_probability,
                "open_set_distance": d.open_set_distance,
                "reconstruction_error": d.reconstruction_error,
                "timestamp": d.created_at.isoformat()
            }
            for d in candidates[:20]
        ]
    }


# -------------------------------------------------------------------
# 4. Incidents (/api/incidents, /api/incidents/{id})
# -------------------------------------------------------------------
@router.get("/incidents", response_model=List[IncidentResponse])
def get_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieve multi-stage correlated incidents."""
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(desc(Incident.overall_risk_score)).limit(limit).all()


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    """Get complete details for a specific incident."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc


@router.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: str,
    status: str = Query(..., pattern="^(OPEN|open|NEEDS_REVIEW|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE)$"),
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("analyst", "admin")),
):
    """Update investigation status of an incident."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    previous_status = inc.status
    inc.status = status
    inc.last_updated_at = datetime.now(timezone.utc)
    record_analyst_activity(
        db, analyst.username, "status_changed", "incident", incident_id,
        {"old_status": previous_status, "new_status": status},
    )
    db.commit()
    db.refresh(inc)
    return {"incident_id": incident_id, "status": inc.status}


@router.post("/incidents/{incident_id}/notes", response_model=InvestigationNoteResponse)
def add_incident_note(
    incident_id: str,
    note_in: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("analyst", "admin")),
):
    """Attach an analyst investigation note to an incident."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    note = InvestigationNote(
        note_id=f"note_{uuid.uuid4().hex[:12]}",
        incident_id=incident_id,
        author=analyst.username,
        content=note_in.content,
        is_ai_generated=False,
        created_at=datetime.now(timezone.utc)
    )
    db.add(note)
    record_analyst_activity(
        db, analyst.username, "note_added", "incident", incident_id,
        {"note_id": note.note_id, "content_length": len(note.content)},
    )
    db.commit()
    db.refresh(note)
    return note


# -------------------------------------------------------------------
# 5. Explainability (/api/explainability/{id})
# -------------------------------------------------------------------
@router.get("/explainability/{incident_id}")
def get_explainability(
    incident_id: str,
    db: Session = Depends(get_db),
):
    """Compute and cache signed LightGBM TreeSHAP attributions on demand."""
    inc = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    risk_detail = inc.risk_score_detail
    if not risk_detail:
        return {"available": False, "reason": "SHAP not computed"}

    def shap_unavailable(reason: str):
        return {
            "available": False,
            "reason": reason,
            "overall_risk_score": inc.overall_risk_score,
            "risk_breakdown": risk_detail.risk_breakdown,
        }

    incident_event = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.order)
        .first()
    )
    detection = None
    event = None
    if incident_event:
        event = db.query(SecurityEvent).filter(SecurityEvent.event_id == incident_event.event_id).first()
        detection = db.query(DetectionResult).filter(DetectionResult.event_id == incident_event.event_id).first()
    if not event or not detection or not detection.details or not detection.details.get("cicids_features"):
        return shap_unavailable("SHAP not computed")

    stored_features = risk_detail.top_contributing_features
    if stored_features and not all("value" in item for item in stored_features):
        stored_features = None
    top_features = _SHAP_CACHE.get(detection.detection_id) or stored_features
    if not top_features:
        try:
            from app.detection.engine import load_model_bundle
            import numpy as np
            import shap
            from ml.preprocessing.cicids_pipeline import apply_log1p_columns

            bundle = load_model_bundle()
            if not bundle:
                return shap_unavailable("SHAP not computed")
            feature_names = bundle["feature_names"]
            raw = detection.details["cicids_features"]
            row = np.asarray([[raw[name] for name in feature_names]], dtype=np.float32)
            transformed = apply_log1p_columns(row, np.asarray(bundle["log1p_columns"], dtype=bool))
            scaled = bundle["scaler"].transform(transformed)
            class_index = bundle["class_names"].index(detection.predicted_class)
            values = shap.TreeExplainer(bundle["model"]).shap_values(scaled)
            if isinstance(values, list):
                signed_values = np.asarray(values[class_index])[0]
            else:
                values = np.asarray(values)
                if values.ndim == 3 and values.shape[-1] == len(bundle["class_names"]):
                    signed_values = values[0, :, class_index]
                elif values.ndim == 3 and values.shape[0] == len(bundle["class_names"]):
                    signed_values = values[class_index, 0, :]
                else:
                    signed_values = values[0] if values.ndim == 2 else values
            top_indexes = np.argsort(np.abs(signed_values))[-5:][::-1]
            top_features = [
                {"feature": feature_names[int(index)], "value": float(signed_values[index])}
                for index in top_indexes
            ]
            _SHAP_CACHE[detection.detection_id] = top_features
            risk_detail.top_contributing_features = top_features
            db.commit()
        except Exception:
            logger.exception("TreeSHAP computation failed for incident %s", incident_id)
            return shap_unavailable("SHAP computation failed")

    return {
        "incident_id": incident_id,
        "title": inc.title,
        "overall_risk_score": inc.overall_risk_score,
        "severity": inc.severity,
        "threat_classification": inc.threat_classification,
        "shap_feature_importance": top_features,
        "risk_breakdown": risk_detail.risk_breakdown,
        "layer_breakdown": {
            "user_identity": risk_detail.user_risk_component,
            "endpoint_device": risk_detail.endpoint_risk_component,
            "network_traffic": risk_detail.network_risk_component,
        },
        "anomaly_factor": risk_detail.anomaly_factor,
        "explanation": risk_detail.explanation_summary
    }


# -------------------------------------------------------------------
# 6. RAG Chat (/api/rag/chat)
# -------------------------------------------------------------------
@router.post("/rag/chat", response_model=RAGChatResponse)
def rag_chat(
    request: RAGChatRequest,
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("analyst", "admin")),
):
    """Grounded cybersecurity investigation assistance."""
    # Find incident if provided
    inc = None
    if request.incident_id:
        inc = db.query(Incident).filter(Incident.incident_id == request.incident_id).first()

    from app.rag.assistant import query_rag_assistant
    return query_rag_assistant(query=request.query, incident=inc, db=db)


# -------------------------------------------------------------------
# 7. Model Retraining & Status (/api/models/retrain, /api/models/status)
# -------------------------------------------------------------------
@router.get("/datasets/cicids")
def get_cicids_dataset_info():
    """Return actual availability details for the legacy CICIDS files."""
    from app.ingestion.cicids_loader import get_available_cicids_files
    files = get_available_cicids_files()
    return {
        "dataset_name": "CICIDS2017 (Canadian Institute for Cybersecurity, University of New Brunswick)",
        "files": files,
        "available_files": sum(1 for item in files.values() if item["is_present"]),
        "checked_files": len(files),
    }


@router.post("/models/retrain")
def retrain_model(
    request: RetrainRequest,
    admin: AnalystAccount = Depends(require_roles("admin")),
):
    """Train a profile in the background and atomically install on success."""
    import os
    from pathlib import Path
    from app.detection.engine import MODEL_BUNDLE_PATH
    from ml.training.train_final import ARTIFACT_PATH, MEDIUM_ARTIFACT_PATH

    target = Path(ARTIFACT_PATH if request.profile == "light" else MEDIUM_ARTIFACT_PATH)
    job_id = uuid.uuid4().hex
    temporary = target.with_name(f".{target.name}.{job_id}.tmp")
    with _RETRAIN_JOBS_LOCK:
        if any(job.get("status") == "running" for job in _RETRAIN_JOBS.values()):
            raise HTTPException(status_code=409, detail="A model retraining job is already running.")
        _RETRAIN_JOBS[job_id] = {
            "status": "running", "profile": request.profile,
            "artifact_path": str(target), "error": None,
        }

    def run_training():
        try:
            from ml.training.train_final import train_final
            trained_path = train_final(profile=request.profile, output_path=temporary)
            if not Path(trained_path).is_file():
                raise FileNotFoundError(f"Training completed without producing artifact: {trained_path}")
            import joblib
            staged_bundle = joblib.load(trained_path)
            if not isinstance(staged_bundle, dict) or not staged_bundle.get("model_version"):
                raise ValueError("Training produced an invalid model bundle.")
            # Same-directory replacement is atomic; the current bundle remains intact until here.
            os.replace(trained_path, target)
            if target.resolve() == Path(MODEL_BUNDLE_PATH).resolve():
                from app.detection import engine as detection_engine
                detection_engine._MODEL_BUNDLE_CACHE = staged_bundle
            with _RETRAIN_JOBS_LOCK:
                _RETRAIN_JOBS[job_id].update(status="completed", artifact_path=str(target), error=None)
        except Exception as exc:
            try:
                Path(temporary).unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove temporary model artifact %s", temporary)
            logger.exception("CICIDS %s profile retraining failed", request.profile)
            with _RETRAIN_JOBS_LOCK:
                _RETRAIN_JOBS[job_id].update(status="failed", error=str(exc))

    threading.Thread(target=run_training, name=f"retrain-{request.profile}-{job_id[:8]}", daemon=True).start()
    return {"status": "running", "job_id": job_id, "profile": request.profile}


@router.get("/models/retrain/status/{job_id}")
def get_retrain_status(job_id: str):
    with _RETRAIN_JOBS_LOCK:
        job = _RETRAIN_JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Retraining job not found.")
        return {"job_id": job_id, **job}


@router.get("/models/status")
def get_model_status():
    """Retrieve status of saved ML model artifacts."""
    from ml.models.registry import get_models_status
    return get_models_status()


# -------------------------------------------------------------------
# 8. Log Ingestion & Upload (/api/upload, /api/analyze)
# -------------------------------------------------------------------
@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    detect: bool = Query(False),
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("analyst", "admin")),
):
    """Upload CSV or JSON logs, optionally scoring CICIDS flow rows."""
    from app.core.config import settings
    from app.ingestion.parser import count_upload_rows, process_uploaded_log_file
    if not file.filename or not file.filename.lower().endswith((".csv", ".json")):
        raise HTTPException(status_code=400, detail="Only .csv and .json uploads are accepted.")
    limit = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    contents = await file.read(limit + 1)
    if len(contents) > limit:
        raise HTTPException(status_code=413, detail=f"Upload exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB limit.")
    try:
        row_count = count_upload_rows(file.filename, contents)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if row_count > 5000:
        job_id = uuid.uuid4().hex
        with _UPLOAD_JOBS_LOCK:
            _UPLOAD_JOBS[job_id] = {"status": "queued", "progress": {"rows_read": 0, "total_rows": row_count}}

        def run_upload():
            with SessionLocal() as job_db:
                def update_progress(progress):
                    with _UPLOAD_JOBS_LOCK:
                        current = _UPLOAD_JOBS.get(job_id)
                        if current is not None:
                            current["progress"].update(progress)
                try:
                    with _UPLOAD_JOBS_LOCK:
                        _UPLOAD_JOBS[job_id]["status"] = "running"
                    result = process_uploaded_log_file(file.filename, contents, job_db, detect, update_progress)
                    with _UPLOAD_JOBS_LOCK:
                        _UPLOAD_JOBS[job_id].update(status="completed", progress={"rows_read": row_count, "total_rows": row_count}, result=result)
                except Exception as exc:
                    job_db.rollback()
                    logger.exception("Background upload job %s failed", job_id)
                    with _UPLOAD_JOBS_LOCK:
                        _UPLOAD_JOBS[job_id].update(status="failed", error=str(exc))

        threading.Thread(target=run_upload, name=f"upload-{job_id[:8]}", daemon=True).start()
        return {"status": "queued", "job_id": job_id, "progress": {"rows_read": 0, "total_rows": row_count}}
    try:
        return process_uploaded_log_file(file.filename, contents, db, detect=detect)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/upload/status/{job_id}")
def get_upload_status(job_id: str):
    with _UPLOAD_JOBS_LOCK:
        job = _UPLOAD_JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Upload job not found.")
        return {**job, "progress": dict(job.get("progress", {}))}


@router.post("/analyze")
async def analyze_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db),
    analyst: AnalystAccount = Depends(require_roles("analyst", "admin")),
):
    """Analyze a single incoming security event through the ML pipeline."""
    from app.detection.engine import process_single_event
    return await process_single_event(event_in=event_in, db=db)


# -------------------------------------------------------------------
# 9. CICIDS2017 Evaluation Results (read from JSON files, never hardcoded)
# -------------------------------------------------------------------

@router.get("/evaluation/results")
def get_evaluation_results(
    run_id: Optional[str] = Query(None),
    include_archive: bool = Query(False),
):
    """List complete runs and return the newest or requested run from disk."""
    from app.services.evaluation_results import get_evaluation_result, list_evaluation_runs

    result = get_evaluation_result(run_id, include_archive=include_archive)
    if result is None:
        if run_id:
            raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found")
        return {
            "available": False,
            "runs": list_evaluation_runs(include_archive=include_archive),
            "message": "No complete evaluation results found. Run backend/ml/run_cicids_eval.py first.",
        }
    return result


@router.get("/evaluation/summary")
def get_evaluation_summary(include_archive: bool = Query(False)):
    """Summarize per-family metrics across complete evaluation seeds, read-only."""
    from app.services.evaluation_results import build_evaluation_summary

    return {"profiles": build_evaluation_summary(include_archive=include_archive)}


@router.post("/evaluation/run")
def trigger_evaluation_run(
    force_reload: bool = Query(False, description="Force re-read of CSVs (clears Parquet cache)"),
    seed: int = Query(42),
    sample: float = Query(1.0, gt=0.0, le=1.0),
    log1p: bool = Query(False),
    admin: AnalystAccount = Depends(require_roles("admin")),
):
    """
    Trigger the full CICIDS2017 evaluation pipeline in a background thread.
    Results are saved to backend/ml/evaluation/results/ and read by /api/evaluation/results.
    NOTE: This is a long-running task (5-30 min). Use wisely.
    """
    import sys
    from pathlib import Path as P
    job_id = str(uuid.uuid4())
    with _EVALUATION_JOBS_LOCK:
        _EVALUATION_JOBS[job_id] = {"status": "running", "error": None}

    def _run():
        try:
            sys.path.insert(0, str(P(__file__).resolve().parents[3]))
            from ml.preprocessing.cicids_pipeline import build_full_pipeline
            from ml.evaluation.known_classifier import run_known_classifier
            from ml.evaluation.open_set_pipeline import run_open_set_evaluation
            pipeline = build_full_pipeline(force_reload=force_reload, seed=seed,
                                           sample=sample, log1p=log1p)
            cls_results, lgbm_model, xgb_model = run_known_classifier(pipeline)
            del lgbm_model, xgb_model
            for key in ("X_train", "y_train", "X_val", "y_val", "X_test", "y_test",
                        "scaler", "le", "full_df"):
                pipeline.pop(key, None)
            import gc
            gc.collect()
            os_results = run_open_set_evaluation(pipeline)
            with _EVALUATION_JOBS_LOCK:
                _EVALUATION_JOBS[job_id] = {
                    "status": "done", "error": None,
                    "known_classifier_results_path": cls_results["results_path"],
                    "open_set_results_path": os_results["results_path"],
                }
        except Exception as exc:
            with _EVALUATION_JOBS_LOCK:
                _EVALUATION_JOBS[job_id] = {"status": "failed", "error": str(exc)}

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return {
        "status": "running", "job_id": job_id,
        "message": "Evaluation pipeline started in background. Poll its status endpoint.",
        "note": "This may take 5-30 minutes depending on hardware."
    }


@router.get("/evaluation/status/{job_id}")
def get_evaluation_status(job_id: str):
    with _EVALUATION_JOBS_LOCK:
        job = _EVALUATION_JOBS.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Evaluation job not found")
    return {"job_id": job_id, **job}
