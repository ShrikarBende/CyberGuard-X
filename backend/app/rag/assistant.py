"""Evidence-grounded investigation answers from stored incidents and retrieved docs."""
from __future__ import annotations

import json
import re
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import DetectionResult, Incident, IncidentEvent
from app.rag.indexer import get_retriever

NOT_ENOUGH_DOCUMENTATION = "I don't have enough documentation to answer this."


def _is_remediation_execution_request(query: str) -> bool:
    text = query.lower()
    asks_to_execute = re.search(r"\b(run|execute|perform|carry out|apply|do)\b", text)
    remediation = re.search(
        r"\b(remediation|containment|isolate|block|disable|revoke|reset|kill|quarantine)\b", text
    )
    return bool(asks_to_execute and remediation)


def _stored_incident_evidence(incident: Incident | None, db: Session) -> tuple[list[dict], str, str]:
    if incident is None:
        return [], "", ""

    event_ids = [
        row.event_id for row in db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.incident_id)
        .order_by(IncidentEvent.order.asc(), IncidentEvent.id.asc()).all()
    ]
    sequence = incident.attack_sequence or []
    if not event_ids:
        event_ids = list(dict.fromkeys(
            event_id for item in sequence for event_id in item.get("event_ids", [])
        ))

    detections = []
    if event_ids:
        detections = db.query(DetectionResult).filter(DetectionResult.event_id.in_(event_ids)).all()
    indicator_rows = (incident.evidence or {}).get("indicators", [])
    if not indicator_rows:
        indicator_rows = sequence
    indicators = []
    for item in indicator_rows:
        name = item.get("name") or item.get("indicator") or item.get("stage")
        if name:
            indicators.append({
                "name": name,
                "event_ids": item.get("event_ids", []),
                "evidence": item.get("evidence", {}),
            })

    mitre_rows = [
        {
            "tactic": row.tactic,
            "technique_id": row.technique_id,
            "technique_name": row.technique_name,
            "confidence": row.confidence,
            "is_verified": row.is_verified,
        }
        for row in incident.mitre_mappings
    ]
    verdicts = [row.verdict for row in detections]
    predicted_classes = list(dict.fromkeys(
        row.predicted_class for row in detections if row.predicted_class
    ))
    scores = [
        {
            "event_id": row.event_id,
            "score": row.score if row.score is not None else row.confidence,
            "probability": row.probability,
            "attack_probability": row.attack_probability if row.attack_probability is not None else row.anomaly_score,
            "open_set_distance": row.open_set_distance,
            "tau": row.tau,
            "score_name": (row.details or {}).get("score_name"),
        }
        for row in detections
    ]

    values = [
        {"field": "incident_id", "value": incident.incident_id},
        {"field": "verdict", "value": verdicts or [incident.threat_classification]},
        {"field": "predicted_class", "value": predicted_classes},
        {"field": "risk_score", "value": incident.overall_risk_score},
        {"field": "scores", "value": scores},
        {"field": "tau", "value": [row.tau for row in detections if row.tau is not None]},
        {"field": "indicators", "value": indicators},
        {"field": "event_ids", "value": event_ids},
        {"field": "mitre", "value": mitre_rows},
    ]
    query_terms = [*predicted_classes, *[row["name"] for row in indicators],
                   *[row["technique_id"] for row in mitre_rows]]
    retrieval_suffix = " ".join(dict.fromkeys(query_terms))
    return values, retrieval_suffix, json.dumps(values, ensure_ascii=False, default=str)


def _llm_answer(query: str, evidence_json: str, chunks: list[dict[str, Any]]) -> str:
    system_prompt = (
        "You are a read-only cybersecurity investigation assistant. Use only the supplied incident evidence "
        "and retrieved documentation chunks. Cite chunk ids exactly as [chunk_id]. Never state that an attack "
        "is confirmed. Never claim that you executed or will execute an action. Say plainly when evidence is "
        "missing. Containment or remediation may only be recommended for analyst approval. If asked to run "
        "remediation, refuse. Do not add outside facts or infer missing evidence."
    )
    user_content = json.dumps({
        "question": query,
        "incident_evidence": json.loads(evidence_json) if evidence_json else [],
        "retrieved_chunks": [
            {"chunk_id": row["chunk_id"], "title": row["title"], "section_title": row["section_title"], "text": row["text"]}
            for row in chunks
        ],
    }, ensure_ascii=False)
    response = httpx.post(
        settings.LLM_API_URL,
        headers={"Authorization": f"Bearer {settings.LLM_API_KEY}"},
        json={
            "model": settings.LLM_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0,
        },
        timeout=45,
    )
    response.raise_for_status()
    payload = response.json()
    answer = (payload.get("choices", [{}])[0].get("message", {}).get("content")
              or payload.get("output_text") or payload.get("answer"))
    if not isinstance(answer, str) or not answer.strip():
        raise ValueError("Configured LLM returned no answer text.")
    return answer.strip()


def _extractive_answer(evidence_values: list[dict], chunks: list[dict[str, Any]], incident: Incident | None) -> str:
    parts = []
    if incident is not None:
        parts.append("Stored incident evidence:\n" + "\n".join(
            f"{row['field']}: {json.dumps(row['value'], ensure_ascii=False, default=str)}"
            for row in evidence_values
        ))
        indicators = next((row["value"] for row in evidence_values if row["field"] == "indicators"), [])
        if not indicators:
            parts.append("Evidence is missing: this incident has no stored indicators.")
    parts.extend(f"[{row['chunk_id']}] {row['text']}" for row in chunks)
    return "\n\n".join(parts)


def query_rag_assistant(query: str, incident: Incident | None, db: Session) -> dict:
    """Retrieve semantic knowledge chunks and answer from chunks plus stored DB evidence."""
    evidence_values, incident_terms, evidence_json = _stored_incident_evidence(incident, db)
    if _is_remediation_execution_request(query):
        return {
            "answer": "I cannot run remediation or take containment actions. I can only provide recommendations for analyst approval.",
            "mode": "extractive",
            "sources": [],
            "evidence_used": evidence_values,
            "confidence": None,
        }

    retrieval_query = f"{query} {incident_terms}".strip()
    retriever = get_retriever()
    retrieved = retriever.search(retrieval_query, settings.RAG_TOP_K)
    if not retrieved or retrieved[0]["score"] < settings.RAG_MIN_RETRIEVAL_SCORE:
        return {
            "answer": NOT_ENOUGH_DOCUMENTATION,
            "mode": "extractive",
            "sources": [],
            "evidence_used": evidence_values,
            "confidence": None,
        }

    sources = [
        {"chunk_id": row["chunk_id"], "title": row["title"], "score": round(float(row["score"]), 6)}
        for row in retrieved
    ]
    if settings.LLM_API_URL and settings.LLM_API_KEY:
        answer = _llm_answer(query, evidence_json, retrieved)
        source_ids = ", ".join(f"[{source['chunk_id']}]" for source in sources)
        if source_ids and not any(source["chunk_id"] in answer for source in sources):
            answer = f"{answer}\n\nSources: {source_ids}"
        mode = "llm"
    else:
        answer = _extractive_answer(evidence_values, retrieved, incident)
        mode = "extractive"
    return {
        "answer": answer,
        "mode": mode,
        "sources": sources,
        "evidence_used": evidence_values,
        "confidence": None,
    }


def _resolved_incident_documents(db: Session, exclude_incident_id: str | None = None) -> list[dict[str, Any]]:
    """Build retrieval documents from analyst-resolved incidents in the database."""
    query = db.query(Incident).filter(Incident.status.in_(["RESOLVED", "FALSE_POSITIVE", "CONFIRMED"]))
    if exclude_incident_id:
        query = query.filter(Incident.incident_id != exclude_incident_id)
    documents = []
    for incident in query.order_by(Incident.last_updated_at.desc()).limit(100).all():
        evidence = incident.evidence or {}
        documents.append({
            "doc_id": f"past-incident:{incident.incident_id}",
            "chunk_id": f"past-incident:{incident.incident_id}:summary",
            "file_id": f"past-incident:{incident.incident_id}",
            "source_file": "resolved_incident_database",
            "source_type": "past_incident",
            "title": incident.title,
            "section_title": "Analyst-verified historical incident",
            "text": (f"Historical incident {incident.incident_id}. Status={incident.status}. "
                     f"Classification={incident.threat_classification}. Severity={incident.severity}. "
                     f"Indicators={json.dumps(evidence.get('indicators', []), ensure_ascii=False, default=str)}. "
                     f"Summary={incident.description or ''}"),
        })
    return documents


def _incident_investigation_evidence(incident: Incident, db: Session) -> dict[str, Any]:
    evidence_values, _terms, _json = _stored_incident_evidence(incident, db)
    incident_event_rows = (db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.incident_id)
                           .order_by(IncidentEvent.order.asc(), IncidentEvent.id.asc()).all())
    event_ids = [row.event_id for row in incident_event_rows]
    detections = db.query(DetectionResult).filter(DetectionResult.event_id.in_(event_ids)).all() if event_ids else []
    layer_scores: dict[str, float] = {}
    signals = {"shap": [], "endpoint_residuals": [], "temporal_attention": [], "graph_attention": [], "open_set": []}
    for detection in detections:
        details = detection.details or {}
        signals_by_layer = {
            "user": details.get("user_sequence") or {},
            "endpoint": details,
            "network": details,
        }
        raw_score = details.get(f"s_{detection.layer}", detection.attack_probability or detection.score or 0.0)
        layer_scores[detection.layer] = max(layer_scores.get(detection.layer, 0.0), float(raw_score or 0.0))
        network_flow = details.get("s_network_flow")
        if network_flow is not None:
            layer_scores["network_flow"] = max(layer_scores.get("network_flow", 0.0), float(network_flow))
        for key, value in (("shap", details.get("shap_feature_importance") or details.get("top_contributing_features")),
                           ("endpoint_residuals", details.get("feature_residuals")),
                           ("temporal_attention", signals_by_layer["user"].get("temporal_attention") or details.get("temporal_attention")),
                           ("graph_attention", (details.get("network_graph") or {}).get("top_suspicious_edges") or details.get("top_suspicious_edges"))):
            if value:
                signals[key].append({"event_id": detection.event_id, "evidence": value})
        if details.get("open_set_score") is not None or detection.verdict in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"}:
            signals["open_set"].append({"event_id": detection.event_id, "verdict": detection.verdict,
                                        "open_set_score": details.get("open_set_score"),
                                        "centroid_distance": details.get("centroid_distance", detection.open_set_distance)})
    fusion = (incident.evidence or {}).get("risk_fusion", {})
    if not fusion and incident.risk_score_detail and incident.risk_score_detail.risk_breakdown:
        fusion = incident.risk_score_detail.risk_breakdown.get("fusion", {})
    return {"incident": {"incident_id": incident.incident_id, "title": incident.title,
                         "status": incident.status, "severity": incident.severity,
                         "threat_classification": incident.threat_classification,
                         "overall_risk_score": incident.overall_risk_score},
            "indicators": evidence_values, "layer_scores": layer_scores,
            "risk_contributions": fusion.get("contributions", {}), "signals": signals,
            "timeline": incident.attack_sequence or []}


def investigate_incident(incident: Incident, db: Session, top_k: int | None = None) -> dict[str, Any]:
    """Run retrieve -> analyze -> map -> summarize -> recommend, with no side effects."""
    evidence = _incident_investigation_evidence(incident, db)
    unknown = incident.threat_classification in {"UNKNOWN_CANDIDATE", "UNKNOWN_NOVEL"}
    query = " ".join([incident.title, incident.threat_classification,
                      json.dumps(evidence["indicators"], ensure_ascii=False, default=str),
                      json.dumps(evidence["layer_scores"]), "unknown novel" if unknown else ""])
    retrieved = get_retriever().search(query, top_k=top_k,
        extra_documents=_resolved_incident_documents(db, incident.incident_id))
    minimum = float(settings.RAG_MIN_RETRIEVAL_SCORE)
    grounded = [item for item in retrieved if float(item.get("relevance_score", item.get("score", 0.0))) >= minimum]
    retrieve = {"step": "retrieve", "query": query, "minimum_relevance_score": minimum,
                "evidence_sufficient": bool(grounded),
                "results": [{"chunk_id": item.get("chunk_id"), "doc_id": item.get("doc_id"),
                             "source_type": item.get("source_type"), "title": item.get("title"),
                             "score": float(item.get("score", 0.0)),
                             "relevance_score": float(item.get("relevance_score", item.get("score", 0.0))),
                             "text": item.get("text", "")} for item in retrieved]}
    analyze = {"step": "analyze", "risk_score": incident.overall_risk_score,
               "severity": incident.severity, "layer_scores": evidence["layer_scores"],
               "risk_contributions": evidence["risk_contributions"], "evidence_signals": evidence["signals"]}
    telemetry = json.dumps(evidence, ensure_ascii=False, default=str).lower()
    mappings = []
    if grounded:
        for item in grounded:
            if item.get("source_type") != "mitre":
                continue
            full_text = f"{item.get('title', '')} {item.get('text', '')}"
            match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", full_text)
            if not match:
                continue
            terms = item.get("supported_indicators") or re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", item.get("title", ""))
            matched = sorted(set(str(term).lower() for term in terms if str(term).lower() in telemetry))
            if matched:
                mappings.append({"technique_id": match.group(1), "technique_name": item.get("title"),
                                 "evidence_terms": matched, "source_chunk_id": item.get("chunk_id"),
                                 "confidence": "evidence_supported"})
    map_step = {"step": "map", "mitre_attack": mappings,
                "statement": ("Technique mapping requires both retrieved documentation and matching incident telemetry."
                              if mappings else "Evidence is insufficient for a supported MITRE ATT&CK technique mapping.")}
    indicators = evidence["indicators"]
    timeline = evidence["timeline"]
    summary = (f"{incident.title}: {incident.severity} risk score {float(incident.overall_risk_score):.1f}. "
               f"Stored evidence includes {len(indicators)} indicator records across {len(evidence['layer_scores'])} scored layers. "
               + ("The event is an unknown/novel candidate and is not confirmed as an attack. " if unknown else
                  "The incident remains analyst-reviewable and is not asserted as a confirmed attack. ")
               + (f"The timeline contains {len(timeline)} recorded stages." if timeline else "No ordered timeline stages are stored."))
    summarize = {"step": "summarize", "executive_summary": summary, "timeline": timeline,
                 "certainty": "unconfirmed"}
    actions = ([{"action": "Preserve relevant authentication, endpoint, and network telemetry for review.",
                 "requires_human_approval": True},
                {"action": "Validate account and host ownership before considering containment.",
                 "requires_human_approval": True}] if grounded else [])
    recommend = {"step": "recommend", "actions": actions, "requires_human_approval": True,
                 "statement": "Recommendations are advisory; this workflow does not execute actions."}
    return {"incident_id": incident.incident_id, "read_only": True,
            "trace": [retrieve, analyze, map_step, summarize, recommend]}
