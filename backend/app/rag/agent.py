"""Small deterministic tool-using investigation prototype (read-only)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.entities import DetectionResult, Incident, IncidentEvent, SecurityEvent
from app.rag.indexer import get_retriever


def tool_lookup_mitre(technique_id: str) -> list[dict]:
    """Retrieve ATT&CK references matching a technique identifier."""
    return get_retriever().search(technique_id, top_k=5)


def tool_query_telemetry(incident_id: str, db: Session) -> list[dict]:
    links = (db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id)
             .order_by(IncidentEvent.order.asc(), IncidentEvent.id.asc()).all())
    events = []
    for link in links:
        event = db.query(SecurityEvent).filter(SecurityEvent.event_id == link.event_id).first()
        if event:
            events.append({"event_id": event.event_id, "timestamp": event.timestamp.isoformat(),
                           "category": event.event_category, "type": event.event_type,
                           "source_ip": event.source_ip, "destination_ip": event.destination_ip,
                           "user_id": event.user_id, "device_id": event.device_id,
                           "process_name": event.process_name})
    return events


def tool_check_novelty(event_id: str, db: Session) -> dict:
    result = db.query(DetectionResult).filter(DetectionResult.event_id == event_id).first()
    if not result:
        return {"event_id": event_id, "available": False}
    details = result.details or {}
    return {"event_id": event_id, "available": True, "verdict": result.verdict,
            "centroid_distance": result.open_set_distance,
            "energy_score": details.get("energy_score", details.get("open_set_score")),
            "score": result.score}


def run_agentic_investigation(incident_id: str, db: Session) -> dict:
    """Select read-only evidence tools based on incident and telemetry contents."""
    incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
    if incident is None:
        raise ValueError(f"Incident {incident_id} was not found")
    telemetry = tool_query_telemetry(incident_id, db)
    event_ids = [row["event_id"] for row in telemetry]
    novelty = [tool_check_novelty(event_id, db) for event_id in event_ids
               if incident.threat_classification in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"}]
    evidence_text = " ".join([incident.title, incident.threat_classification,
                               " ".join(row["type"] for row in telemetry)]).lower()
    terms = {"T1110": ("login", "auth", "brute"), "T1059.001": ("powershell",),
             "T1046": ("scan", "portscan"), "T1021.002": ("smb", "share"),
             "T1041": ("exfil", "transfer")}
    mappings = []
    for technique, hints in terms.items():
        if any(hint in evidence_text for hint in hints):
            docs = tool_lookup_mitre(technique)
            doc = next((d for d in docs if technique.lower() in (d.get("title", "") + " " + d.get("text", "")).lower()), None)
            if doc:
                mappings.append({"technique_id": technique, "source_chunk_id": doc.get("chunk_id"),
                                 "evidence": "matching telemetry signature", "confidence": "evidence_gated"})
    findings = [f"{row['timestamp']} {row['category']}/{row['type']}" for row in telemetry]
    return {"incident_id": incident_id, "read_only": True,
            "root_cause_analysis": "Incident is a reviewable candidate; findings are limited to stored telemetry and retrieved references.",
            "observed_progression": findings,
            "evidence_gated_mitre": mappings,
            "novelty_checks": novelty,
            "containment_recommendations": [
                {"action": "Preserve correlated identity, endpoint, and network evidence.", "requires_human_authorization": True},
                {"action": "Validate account and host ownership before considering containment.", "requires_human_authorization": True}],
            "tool_trace": ["query_telemetry", *("check_novelty" for _ in novelty),
                           *(f"lookup_mitre:{m['technique_id']}" for m in mappings)]}
