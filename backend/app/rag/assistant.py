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
