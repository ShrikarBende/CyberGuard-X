"""Cross-layer rule correlation and incident persistence."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.config import settings
from app.detection.risk import compute_fused_risk
from app.models.entities import (
    DetectionResult, Incident, IncidentEvent, MitreTechnique, RiskScore, SecurityEvent, User, Device,
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
    event_rows = list(events)
    indicators = evaluate_indicators(event_rows)
    event_by_id = {str(getattr(row, "event_id", None) or (row.get("event_id") if isinstance(row, dict) else "")): row
                   for row in event_rows}
    model_indicators = [item for item in indicators if item["name"] == "model_flagged_flow"]
    rule_event_ids = {str(event_id) for item in indicators if item["name"] != "model_flagged_flow"
                      for event_id in item.get("event_ids", [])}
    suppressed_ids: set[str] = set()
    for item in model_indicators:
        event_id = str((item.get("event_ids") or [""])[0])
        event = event_by_id.get(event_id)
        detection = (event.get("detection_result") if isinstance(event, dict) else getattr(event, "detection_result", None)) if event else None
        if not detection:
            continue
        get = (lambda key, default=None: detection.get(key, default)) if isinstance(detection, dict) else (lambda key, default=None: getattr(detection, key, default))
        layer = str(get("layer", "network")).lower()
        details = get("details", {}) or {}
        verdict = str(get("verdict", ""))
        if verdict == "UNKNOWN_NOVEL" or details.get("decision_outcome") == "UNKNOWN_NOVEL":
            continue
        confidence = get("attack_probability")
        if confidence is None:
            confidence = get("probability")
        if confidence is None:
            confidence = get("score")
        confidence = float(confidence or 0.0)
        user_detail = details.get("user_sequence") or {}
        endpoint_score = float(details.get("s_endpoint", details.get("endpoint_score", 0.0)) or 0.0)
        user_score = float(details.get("s_user", user_detail.get("s_user", 0.0)) or 0.0)
        graph_detail = details.get("network_graph") or {}
        graph_score = float(details.get("s_network_graph", graph_detail.get("s_network_graph", 0.0)) or 0.0)
        host_context = details.get("host_window") or {}
        host_burst = (float(host_context.get("win_unique_dst_ports_60s", host_context.get("distinct_dst_ports_1m", 0.0)) or 0.0) >= 10 or
                      float(host_context.get("suspicious_flows_60s", 0.0) or 0.0) >= 5)
        source_ip = str(getattr(event, "source_ip", None) or (event.get("source_ip") if isinstance(event, dict) else ""))
        suspicious_flow_count = 0
        for related in event_rows:
            related_ip = str(getattr(related, "source_ip", None) or (related.get("source_ip") if isinstance(related, dict) else ""))
            if related_ip != source_ip:
                continue
            related_detection = (related.get("detection_result") if isinstance(related, dict) else getattr(related, "detection_result", None))
            if related_detection:
                related_get = (lambda key, default=None: related_detection.get(key, default)) if isinstance(related_detection, dict) else (lambda key, default=None: getattr(related_detection, key, default))
                if related_get("verdict") in {"KNOWN_THREAT", "UNKNOWN_NOVEL"}:
                    suspicious_flow_count += 1
        corroborated = (event_id in rule_event_ids or endpoint_score >= 0.95 or user_score >= 0.5 or
                        graph_score >= 0.5 or host_burst or suspicious_flow_count >= 5)
        if layer == "network" and 0.50 <= confidence < 0.85 and not corroborated:
            suppressed_ids.add(event_id)
            item["suppressed"] = True
    active_indicators = [item for item in indicators
                         if not (item["name"] == "model_flagged_flow" and
                                 str((item.get("event_ids") or [""])[0]) in suppressed_ids)]
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

    for left in range(len(active_indicators)):
        left_keys = _entity_keys(active_indicators[left])
        for right in range(left + 1, len(active_indicators)):
            if active_indicators[right]["timestamp"] - active_indicators[left]["timestamp"] > window:
                break
            if left_keys & _entity_keys(active_indicators[right]):
                union(left, right)

    components: dict[int, list[dict]] = defaultdict(list)
    for index, indicator in enumerate(active_indicators):
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
        if str((indicator.get("event_ids") or [""])[0]) in suppressed_ids:
            serialized["suppressed"] = True
            serialized["alert_status"] = "NOISE_SUPPRESSED"
            serialized["incident_candidate"] = False
        alerts.append(serialized)

    candidates = []
    for group in incident_groups:
        distinct_names = {indicator["name"] for indicator in group}
        layers = sorted({indicator["layer"] for indicator in group})
        has_model_flag = "model_flagged_flow" in distinct_names
        risk = compute_fused_risk({"stage_count": len(distinct_names), "s_network_flow": float(has_model_flag)})
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
            "risk_fusion": risk,
            "description": NOT_CONFIRMED,
            "status": "open",
        })
    raw_alert_count = len(alerts)
    result = {"alerts": alerts, "incidents": candidates, "window_minutes": window.total_seconds() / 60}
    if raw_alert_count:
        result.update({"suppressed_low_confidence_alerts": len(suppressed_ids),
                       "total_raw_alerts": raw_alert_count,
                       "alert_suppression_ratio": len(suppressed_ids) / raw_alert_count})
    return result


MITRE_RULES = {
    "failed_login_burst": ("Credential Access", "T1110", "Brute Force"),
    "encoded_powershell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "privilege_escalation": ("Persistence", "T1098", "Account Manipulation"),
}


def run_correlation(db: Session, window_minutes: int | None = None) -> dict:
    """Run correlation over stored events and persist only incidents and rule evidence."""
    max_ts = db.query(func.max(SecurityEvent.timestamp)).scalar()
    events_query = db.query(SecurityEvent)
    has_demo_replay = db.query(SecurityEvent.event_id).filter(
        SecurityEvent.dataset == "synthetic_demo"
    ).first() is not None
    if max_ts is not None and not has_demo_replay:
        minutes = window_minutes or settings.CORRELATION_WINDOW_MINUTES
        events_query = events_query.filter(SecurityEvent.timestamp >= max_ts - timedelta(minutes=minutes * 4))
    events = events_query.order_by(SecurityEvent.timestamp.asc()).all()
    result = correlate_events(events, window_minutes)
    event_lookup = {event.event_id: event for event in events}
    persisted = []
    for candidate in result["incidents"]:
        indicators = candidate["indicators"]
        indicator_count = len({item["name"] for item in indicators})
        event_ids_for_fusion = list(dict.fromkeys(event_id for item in indicators for event_id in item["event_ids"]))
        detection_rows = (db.query(DetectionResult).filter(DetectionResult.event_id.in_(event_ids_for_fusion)).all()
                          if event_ids_for_fusion else [])
        branch_inputs = {"stage_count": indicator_count}
        for detection_row in detection_rows:
            detail = detection_row.details or {}
            user_data = detail.get("user_sequence") or {}
            graph_data = detail.get("network_graph") or {}
            branch_inputs["s_user"] = max(float(branch_inputs.get("s_user", 0.0)),
                                          float(detail.get("s_user", user_data.get("s_user", 0.0)) or 0.0))
            branch_inputs["s_endpoint"] = max(float(branch_inputs.get("s_endpoint", 0.0)),
                                               float(detail.get("s_endpoint", 0.0) or 0.0))
            branch_inputs["s_network_flow"] = max(float(branch_inputs.get("s_network_flow", 0.0)),
                                                   float(detail.get("s_network_flow", detection_row.attack_probability or 0.0) or 0.0))
            branch_inputs["s_network_graph"] = max(float(branch_inputs.get("s_network_graph", 0.0)),
                                                    float(detail.get("s_network_graph", graph_data.get("s_network_graph", 0.0)) or 0.0))
            open_set_score = detail.get("open_set_score")
            if open_set_score is None and detection_row.open_set_distance is not None:
                distance = float(detection_row.open_set_distance)
                open_set_score = distance / (1.0 + max(distance, 0.0))
            branch_inputs["s_open_set_distance"] = max(float(branch_inputs.get("s_open_set_distance", 0.0)),
                                                        float(open_set_score or 0.0))
        fusion = compute_fused_risk(branch_inputs)
        candidate["risk_score"] = fusion["score"]
        candidate["risk_breakdown"] = fusion["breakdown"]
        candidate["risk_fusion"] = fusion
        signature_source = "|".join(
            f"{item['name']}:{','.join(item['event_ids'])}" for item in indicators
        )
        signature = hashlib.sha256(signature_source.encode("utf-8")).hexdigest()[:20]
        incident_id = f"corr_{signature}"
        existing = db.query(Incident).filter(Incident.incident_id == incident_id).first()
        if existing:
            existing.overall_risk_score = fusion["score"]
            existing.severity = fusion["severity"]
            existing_evidence = dict(existing.evidence or {})
            existing_evidence.update({"risk_fusion": fusion, "risk_breakdown": fusion["breakdown"]})
            existing.evidence = existing_evidence
            detail = db.query(RiskScore).filter(RiskScore.incident_id == incident_id).first()
            if detail:
                detail.score = fusion["score"]
                detail.category = fusion["severity"]
                detail.user_risk_component = fusion["contributions"]["user_contribution"]
                detail.endpoint_risk_component = fusion["contributions"]["endpoint_contribution"]
                detail.network_risk_component = fusion["contributions"]["network_contribution"]
                detail.anomaly_factor = fusion["probability"]
                detail.risk_breakdown = fusion["breakdown"]
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
        severity = candidate["risk_fusion"]["severity"]
        attack_sequence = [
            {"stage": item["name"], "indicator": item["name"], "timestamp": item["timestamp"],
             "event_ids": item["event_ids"], "evidence": item["evidence"], "layer": item["layer"]}
            for item in indicators
        ]
        incident_evidence = {
            "indicators": indicators,
            "layers": candidate["layers"],
            "risk_breakdown": candidate["risk_breakdown"],
            "risk_fusion": candidate["risk_fusion"],
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
            user_risk_component=candidate["risk_fusion"]["contributions"]["user_contribution"],
            endpoint_risk_component=candidate["risk_fusion"]["contributions"]["endpoint_contribution"],
            network_risk_component=candidate["risk_fusion"]["contributions"]["network_contribution"],
            anomaly_factor=candidate["risk_fusion"]["probability"],
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
        "suppressed_low_confidence_alerts": result.get("suppressed_low_confidence_alerts", 0),
        "total_raw_alerts": result.get("total_raw_alerts", len(result["alerts"])),
        "alert_suppression_ratio": result.get("alert_suppression_ratio", 0.0),
        "message": NOT_CONFIRMED,
    }
