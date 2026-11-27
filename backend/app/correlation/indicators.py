"""Rule-based indicators with explicit rules and evidence fields."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
import ipaddress

from app.core.config import settings


def _get(event: Any, name: str, default=None):
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


def _timestamp(event: Any) -> datetime:
    value = _get(event, "timestamp")
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _id(event: Any) -> str:
    return str(_get(event, "event_id", ""))


def _layer(event: Any) -> str:
    category = str(_get(event, "event_category", "")).lower()
    return "user" if category in {"auth", "access"} else "endpoint" if category == "endpoint" else "network"


def _record(name: str, rule: str, event: Any, fields: list[str], *, event_ids=None,
            evidence=None, layer=None, timestamp=None) -> dict:
    return {
        "name": name,
        "source_type": "rule_correlated",
        "dataset": _get(event, "dataset"),
        "scenario": _get(event, "scenario"),
        "is_demo": _get(event, "dataset") == "synthetic_demo",
        "rule": rule,
        "evidence_fields": fields,
        "evidence": evidence or {field: _get(event, field) for field in fields},
        "event_ids": event_ids or [_id(event)],
        "layer": layer or _layer(event),
        "timestamp": timestamp or _timestamp(event),
        "user_id": _get(event, "user_id"),
        "device_id": _get(event, "device_id"),
        "source_ip": _get(event, "source_ip"),
    }


def evaluate_indicators(events: Iterable[Any]) -> list[dict]:
    """Evaluate configured rules. Returned values are indicators, not predictions."""
    rows = sorted(list(events), key=_timestamp)
    indicators: list[dict] = []
    burst_groups: dict[tuple, list[Any]] = defaultdict(list)
    successful_logins: dict[str, list[Any]] = defaultdict(list)
    stuffing_groups: dict[str, list[Any]] = defaultdict(list)

    for event in rows:
        category = str(_get(event, "event_category", "")).lower()
        event_type = str(_get(event, "event_type", "")).lower()
        status = str(_get(event, "status", "")).lower()
        if category == "auth" and "login" in event_type:
            if status in {"failure", "failed", "denied", "blocked"}:
                key = (_get(event, "user_id"), _get(event, "device_id"), _get(event, "source_ip"))
                burst_groups[key].append(event)
                stuffing_groups[str(_get(event, "source_ip") or "")].append(event)
            elif status in {"success", "succeeded", "ok"}:
                successful_logins[str(_get(event, "user_id"))].append(event)

    burst_window = timedelta(minutes=settings.FAILED_LOGIN_BURST_WINDOW_MINUTES)
    for key, failures in burst_groups.items():
        left = 0
        emitted: set[tuple[str, ...]] = set()
        for right, event in enumerate(failures):
            while _timestamp(event) - _timestamp(failures[left]) > burst_window:
                left += 1
            window_events = failures[left:right + 1]
            if len(window_events) >= settings.FAILED_LOGIN_BURST_COUNT:
                event_ids = tuple(_id(item) for item in window_events)
                if event_ids not in emitted:
                    emitted.add(event_ids)
                    indicators.append(_record(
                        "failed_login_burst",
                        f"At least {settings.FAILED_LOGIN_BURST_COUNT} failed logins for one user/device/source IP within {settings.FAILED_LOGIN_BURST_WINDOW_MINUTES} minutes.",
                        event,
                        ["event_type", "status", "user_id", "device_id", "source_ip", "timestamp"],
                        event_ids=list(event_ids),
                        evidence={"count": len(window_events), "event_ids": list(event_ids),
                                  "user_id": key[0], "device_id": key[1], "source_ip": key[2]},
                        layer="user",
                    ))
                    # One alert for the first qualifying rolling window is enough.
                    break

    # A shared external source failing against many distinct identities is a stuffing signal.
    for source_ip, failures in stuffing_groups.items():
        left = 0
        for right, event in enumerate(failures):
            while left < right and _timestamp(event) - _timestamp(failures[left]) > timedelta(minutes=10):
                left += 1
            window = failures[left:right + 1]
            distinct_users = {str(_get(row, "user_id")) for row in window}
            if len(distinct_users) < 10:
                continue
            indicators.append(_record("credential_stuffing_burst",
                "Failed authentication attempts from one source target at least ten distinct users within ten minutes.", event,
                ["event_type", "status", "user_id", "source_ip", "timestamp"],
                event_ids=[_id(row) for row in window],
                evidence={"distinct_users": len(distinct_users), "source_ip": source_ip,
                          "users": sorted(distinct_users)}, layer="user"))
            break

    business_start = settings.BUSINESS_HOURS_START
    business_end = settings.BUSINESS_HOURS_END
    rare_ports = set(settings.RARE_OUTBOUND_PORTS)
    transfer_threshold = settings.LARGE_TRANSFER_BYTES
    for event in rows:
        category = str(_get(event, "event_category", "")).lower()
        event_type = str(_get(event, "event_type", "")).lower()
        timestamp = _timestamp(event)
        if category == "auth" and "login" in event_type and str(_get(event, "status", "")).lower() in {"success", "succeeded", "ok"}:
            user_key = str(_get(event, "user_id"))
            prior_ips = {
                _get(prior, "source_ip") for prior in successful_logins[user_key]
                if _timestamp(prior) < timestamp and _get(prior, "source_ip")
            }
            source_ip = _get(event, "source_ip")
            if prior_ips and source_ip and source_ip not in prior_ips:
                indicators.append(_record(
                    "new_ip_login",
                    "Successful login from a source IP not used by an earlier successful login for the same user in the available event history.",
                    event, ["user_id", "source_ip", "timestamp", "status"],
                    evidence={"user_id": user_key, "source_ip": source_ip,
                              "previous_source_ips": sorted(prior_ips), "status": _get(event, "status")},
                ))
            # Event timestamps are normalized upstream; use their recorded hour
            # directly so demo/test outcomes do not depend on server timezone.
            local_hour = timestamp.hour
            if local_hour < business_start or local_hour >= business_end:
                indicators.append(_record(
                    "off_hours_login",
                    f"Successful login outside configured business hours [{business_start:02d}:00, {business_end:02d}:00).",
                    event, ["user_id", "source_ip", "timestamp", "status"],
                    evidence={"user_id": user_key, "source_ip": source_ip,
                              "local_hour": local_hour, "status": _get(event, "status")},
                ))

        privilege = str(_get(event, "privilege_level", "")).lower()
        payload = _get(event, "raw_payload", {}) or {}
        previous = str(payload.get("previous_privilege", "")).lower() if isinstance(payload, dict) else ""
        new_privilege = str(payload.get("new_privilege", privilege)).lower() if isinstance(payload, dict) else privilege
        if "privilege" in event_type and new_privilege in {"admin", "administrator", "root", "system"} and previous != new_privilege:
            indicators.append(_record(
                "privilege_escalation",
                "Privilege-change event moves the account to admin, administrator, root, or system from a different prior level.",
                event, ["user_id", "device_id", "privilege_level", "event_type", "raw_payload"],
                evidence={"user_id": _get(event, "user_id"), "device_id": _get(event, "device_id"),
                          "previous_privilege": previous or None, "new_privilege": new_privilege},
            ))

        process_name = str(_get(event, "process_name", "")).replace("/", "\\").rsplit("\\", 1)[-1].lower()
        command_line = str(_get(event, "command_line", "")).lower()
        if category == "auth" and event_type == "login_success":
            prior = [row for row in successful_logins[str(_get(event, "user_id"))]
                     if _timestamp(row) < timestamp and _get(row, "source_ip") != _get(event, "source_ip")]
            for previous_login in prior:
                try:
                    close_subnet = ipaddress.ip_address(_get(previous_login, "source_ip")) in ipaddress.ip_network(
                        f"{_get(event, 'source_ip')}/{24 if ':' not in str(_get(event, 'source_ip')) else 64}", strict=False)
                except (ValueError, TypeError):
                    close_subnet = False
                elapsed = (timestamp - _timestamp(previous_login)).total_seconds()
                if 0 <= elapsed <= 30 * 60 and not close_subnet:
                    indicators.append(_record("impossible_travel",
                        "Same user authenticated from IPs in different /24 (IPv4) or /64 (IPv6) subnets within 30 minutes.",
                        event, ["user_id", "source_ip", "timestamp"],
                        event_ids=[_id(previous_login), _id(event)],
                        evidence={"previous_source_ip": _get(previous_login, "source_ip"),
                                  "source_ip": _get(event, "source_ip"), "elapsed_seconds": elapsed}, layer="user"))
                break
        if process_name == "powershell.exe" and any(token in command_line for token in (" -enc ", " -encodedcommand ", " -encodedcommand=")):
            indicators.append(_record(
                "encoded_powershell",
                "Process is powershell.exe and command line contains -enc or -encodedcommand.",
                event, ["process_name", "command_line", "user_id", "device_id"], layer="endpoint",
            ))
        if process_name in {"certutil.exe", "mshta.exe", "bitsadmin.exe"} and any(
            token in command_line for token in ("http://", "https://", "-urlcache", "-url", "http", "transfer")
        ):
            indicators.append(_record("lolbin_execution", "Known LOLBin invoked with remote-fetch indicators.", event,
                ["process_name", "command_line", "user_id", "device_id"], layer="endpoint"))

        if process_name == "vssadmin.exe" and "delete" in command_line and "shadow" in command_line:
            indicators.append(_record("ransomware_burst", "vssadmin shadow-copy deletion command observed.", event,
                ["process_name", "command_line", "user_id", "device_id"], layer="endpoint"))
        if event_type in {"file_modify", "file_write", "file_create"} and str(_get(event, "file_path", "")).lower().endswith(".locked"):
            indicators.append(_record("ransomware_burst", "File activity created or modified a .locked file.", event,
                ["event_type", "file_path", "user_id", "device_id"], layer="endpoint"))

        payload_length = _get(event, "payload_length")
        query_name = str(_get(event, "query_name", ""))
        if category == "network" and event_type == "dns_query" and (int(payload_length or len(query_name)) >= 90):
            indicators.append(_record("dns_tunneling", "DNS query payload/name is at least 90 characters.", event,
                ["event_type", "query_name", "payload_length", "record_type"], layer="network"))

        destination_port = _get(event, "destination_port")
        if category == "network" and destination_port is not None and int(destination_port) in rare_ports:
            indicators.append(_record(
                "rare_port_outbound",
                f"Outbound network event uses a configured rare destination port in {sorted(rare_ports)}.",
                event, ["source_ip", "destination_ip", "destination_port", "event_type"], layer="network",
            ))

        transferred = int(_get(event, "bytes_transferred", 0) or 0)
        if category == "network" and transferred >= transfer_threshold:
            indicators.append(_record(
                "large_transfer",
                f"Network event transfers at least {transfer_threshold} bytes.",
                event, ["source_ip", "destination_ip", "destination_port", "bytes_transferred"],
                evidence={"source_ip": _get(event, "source_ip"),
                          "destination_ip": _get(event, "destination_ip"),
                          "destination_port": destination_port, "bytes_transferred": transferred,
                          "external_destination": None},
                layer="network",
            ))

        detection = _get(event, "detection_result")
        verdict = _get(detection, "verdict") if detection else _get(event, "model_verdict")
        if verdict in {"KNOWN_THREAT", "UNKNOWN_CANDIDATE"}:
            model_score = _get(detection, "score") if detection else _get(event, "model_score")
            indicators.append(_record(
                "model_flagged_flow",
                "Attached CICIDS model result has a non-benign threat-candidate verdict.",
                event, ["event_id", "verdict", "score"],
                evidence={"verdict": verdict, "model_score": model_score},
                layer=str(_get(detection, "layer", "network")) if detection else str(_get(event, "model_layer", "network")),
            ))

    file_activity: dict[str, list[Any]] = defaultdict(list)
    for event in rows:
        event_type = str(_get(event, "event_type", "")).lower()
        if str(_get(event, "event_category", "")).lower() == "endpoint" and event_type in {
            "file_modify", "file_write", "file_create"
        }:
            file_activity[str(_get(event, "device_id") or "")].append(event)
    for device_id, modifications in file_activity.items():
        left = 0
        for right, event in enumerate(modifications):
            while left < right and _timestamp(event) - _timestamp(modifications[left]) > timedelta(minutes=5):
                left += 1
            window = modifications[left:right + 1]
            if len(window) >= 10:
                indicators.append(_record("ransomware_burst",
                    "At least ten file writes/modifications occurred on one device within five minutes.", event,
                    ["event_type", "device_id", "timestamp"], event_ids=[_id(row) for row in window],
                    evidence={"device_id": device_id, "modification_count": len(window),
                              "event_ids": [_id(row) for row in window]}, layer="endpoint"))
                break

    # External-destination evidence is explicit and shared with MITRE gating.
    for indicator in indicators:
        if indicator["name"] == "large_transfer":
            destination = indicator["evidence"].get("destination_ip")
            try:
                address = ipaddress.ip_address(destination)
                external = not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast)
            except (ValueError, TypeError):
                external = False
            indicator["evidence"]["external_destination"] = external
    return sorted(indicators, key=lambda item: item["timestamp"])
