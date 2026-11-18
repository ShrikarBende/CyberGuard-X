"""Cross-layer rule correlation and incident persistence."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

from sqlalchemy.orm import Session

from app.core.config import settings
from app.detection.risk import compute_correlation_risk
from app.models.entities import (
    Incident, IncidentEvent, MitreTechnique, RiskScore, SecurityEvent, User, Device,
)
from app.correlation.indicators import evaluate_indicators

NOT_CONFIRMED = "Correlated suspicious activity; not a confirmed attack."


def _entity_keys(indicator: dict) -> set[tuple[str, str]]:
    return {
        (name, str(indicator[name]))
        for name in ("user_id", "device_id", "source_ip")
        if indicator.get(name)
    }


def _serializable_indicator(indicator: dict) -> dict:
    return {
        **indicator,
        "timestamp": indicator["timestamp"].astimezone(timezone.utc).isoformat(),
    }


def _as_datetime(value):
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def correlate_events(events, window_minutes: int | None = None) -> dict:
    """Evaluate rules, link shared entities within the window, and form incidents."""
    window = timedelta(minutes=window_minutes or settings.CORRELATION_WINDOW_MINUTES)
    indicators = evaluate_indicators(events)
    parent = list(range(len(indicators)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left, right):
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for left in range(len(indicators)):
        left_keys = _entity_keys(indicators[left])
        for right in range(left + 1, len(indicators)):
            if indicators[right]["timestamp"] - indicators[left]["timestamp"] > window:
                break
            if left_keys & _entity_keys(indicators[right]):
                union(left, right)

    components: dict[int, list[dict]] = defaultdict(list)
    for index, indicator in enumerate(indicators):
        components[find(index)].append(indicator)

    incident_groups = []
    for group in components.values():
        names = {indicator["name"] for indicator in group}
        layers = {indicator["layer"] for indicator in group}
        if len(names) >= settings.CORRELATION_MIN_INDICATORS and len(layers) >= settings.CORRELATION_MIN_LAYERS:
            incident_groups.append(sorted(group, key=lambda item: (item["timestamp"], item["name"])))

    incident_indicator_ids = {
        (indicator["name"], tuple(indicator["event_ids"]))
        for group in incident_groups for indicator in group
    }
    alerts = []
    for indicator in indicators:
        serialized = _serializable_indicator(indicator)
        serialized["incident_candidate"] = (
            indicator["name"], tuple(indicator["event_ids"])
        ) in incident_indicator_ids
        alerts.append(serialized)

    candidates = []
    for group in incident_groups:
        distinct_names = {indicator["name"] for indicator in group}
        layers = sorted({indicator["layer"] for indicator in group})
        has_model_flag = "model_flagged_flow" in distinct_names
        risk = compute_correlation_risk(len(distinct_names), len(layers), has_model_flag)
        sequence = []
        for indicator in group:
            item = _serializable_indicator(indicator)
            item["stage"] = item["name"]
            sequence.append(item)
        candidates.append({
            "indicators": sequence,
            "layers": layers,
            "risk_score": risk["score"],
            "risk_breakdown": risk["breakdown"],
            "description": NOT_CONFIRMED,
            "status": "open",
        })
    return {"alerts": alerts, "incidents": candidates, "window_minutes": window.total_seconds() / 60}


MITRE_RULES = {
    "failed_login_burst": ("Credential Access", "T1110", "Brute Force"),
    "encoded_powershell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "privilege_escalation": ("Persistence", "T1098", "Account Manipulation"),
}


def run_correlation(db: Session, window_minutes: int | None = None) -> dict:
    """Run correlation over stored events and persist only incidents and rule evidence."""
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.asc()).all()
    result = correlate_events(events, window_minutes)
    event_lookup = {event.event_id: event for event in events}
    persisted = []
    for candidate in result["incidents"]:
        indicators = candidate["indicators"]
        signature_source = "|".join(
            f"{item['name']}:{','.join(item['event_ids'])}" for item in indicators
        )
        signature = hashlib.sha256(signature_source.encode("utf-8")).hexdigest()[:20]
        incident_id = f"corr_{signature}"
        existing = db.query(Incident).filter(Incident.incident_id == incident_id).first()
        if existing:
            persisted.append(existing)
            continue

        first = min(indicators, key=lambda item: item["timestamp"])
        last = max(indicators, key=lambda item: item["timestamp"])
        event_ids = list(dict.fromkeys(event_id for item in indicators for event_id in item["event_ids"]))
        user_ids = {item.get("user_id") for item in indicators if item.get("user_id")}
        device_ids = {item.get("device_id") for item in indicators if item.get("device_id")}
        user_id = next(iter(user_ids)) if len(user_ids) == 1 else None
        device_id = next(iter(device_ids)) if len(device_ids) == 1 else None
        if user_id and not db.query(User).filter(User.user_id == user_id).first():
            user_id = None
        if device_id and not db.query(Device).filter(Device.device_id == device_id).first():
            device_id = None
        risk_score = candidate["risk_score"]
        severity = "CRITICAL" if risk_score >= settings.RISK_CRITICAL_THRESHOLD else (
            "HIGH" if risk_score >= settings.RISK_HIGH_THRESHOLD else "MEDIUM"
        )
        attack_sequence = [
            {"stage": item["name"], "indicator": item["name"], "timestamp": item["timestamp"],
             "event_ids": item["event_ids"], "evidence": item["evidence"], "layer": item["layer"]}
            for item in indicators
        ]
        incident_evidence = {
            "indicators": indicators,
            "layers": candidate["layers"],
            "risk_breakdown": candidate["risk_breakdown"],
            "correlation_key": signature,
            "notice": NOT_CONFIRMED,
        }
        incident = Incident(
            incident_id=incident_id,
            title=f"Cross-layer suspicious activity: {user_id or device_id or first['user_id'] or 'unattributed'}",
            description=NOT_CONFIRMED,
            severity=severity,
            status="open",
            threat_classification="RULE_CORRELATED_SUSPICIOUS_ACTIVITY",
            overall_risk_score=risk_score,
            user_id=user_id,
            device_id=device_id,
            attack_sequence=attack_sequence,
            evidence=incident_evidence,
            first_detected_at=_as_datetime(first["timestamp"]),
            last_updated_at=_as_datetime(last["timestamp"]),
        )
        db.add(incident)
        db.flush()
        for order, event_id in enumerate(event_ids):
            matching = [item["name"] for item in indicators if event_id in item["event_ids"]]
            if event_id in event_lookup:
                db.add(IncidentEvent(
                    incident_id=incident_id,
                    event_id=event_id,
                    stage=", ".join(matching),
                    order=order,
                ))
        db.add(RiskScore(
            incident_id=incident_id,
            score=risk_score,
            category=severity,
            correlation_multiplier=1.0,
            explanation_summary=NOT_CONFIRMED,
            risk_breakdown=candidate["risk_breakdown"],
        ))
        mitre_names = {item["name"] for item in indicators}
        for name in sorted(mitre_names & MITRE_RULES.keys()):
            tactic, technique_id, technique_name = MITRE_RULES[name]
            evidence_indicators = [item for item in indicators if item["name"] == name]
            db.add(MitreTechnique(
                incident_id=incident_id,
                tactic=tactic,
                technique_id=technique_id,
                technique_name=technique_name,
                confidence="rule_matched",
                evidence_predicate={"indicator": name, "evidence": [item["evidence"] for item in evidence_indicators]},
                is_verified=False,
            ))
        if "large_transfer" in mitre_names:
            external_transfer = any(
                item["name"] == "large_transfer" and item["evidence"].get("external_destination")
                for item in indicators
            )
            if external_transfer:
                db.add(MitreTechnique(
                    incident_id=incident_id,
                    tactic="Exfiltration",
                    technique_id="T1041",
                    technique_name="Exfiltration Over C2 Channel",
                    confidence="rule_matched",
                    evidence_predicate={"indicator": "large_transfer", "destination_external": True},
                    is_verified=False,
                ))
        persisted.append(incident)

    db.commit()
    for incident in persisted:
        db.refresh(incident)
    return {
        "alerts": result["alerts"],
        "incidents": persisted,
        "window_minutes": result["window_minutes"],
        "message": NOT_CONFIRMED,
    }
