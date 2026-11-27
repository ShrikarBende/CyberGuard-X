"""Strict, row-tolerant parsing for uploaded CSV and JSON telemetry."""
from __future__ import annotations

import csv
import io
import json
import math
import uuid
from collections import Counter
from datetime import datetime
from typing import Any, Callable, Dict, Iterable

import pandas as pd
from sqlalchemy.orm import Session

from app.core.config import settings
from app.ingestion.dedup import stable_event_hash
from app.models.entities import Device, SecurityEvent, User


ProgressCallback = Callable[[dict[str, Any]], None]


def _lookup(raw: Dict[str, Any], *names: str) -> Any:
    indexed = {str(key).strip().casefold(): value for key, value in raw.items() if key is not None}
    for name in names:
        value = indexed.get(name.strip().casefold())
        if value is not None and not (isinstance(value, str) and not value.strip()):
            return value
    return None


def parse_timestamp(value: Any) -> datetime:
    """Parse timestamps to UTC; invalid or missing values are rejected by the caller."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise ValueError("missing timestamp")
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not math.isfinite(float(value)):
                raise ValueError("timestamp must be finite")
            parsed = pd.to_datetime(value, unit="s", utc=True, errors="raise")
        else:
            parsed = pd.to_datetime(value, format="mixed", utc=True, errors="raise")
    except (TypeError, ValueError, OverflowError) as first_error:
        if isinstance(value, (int, float)):
            raise ValueError(f"invalid timestamp {value!r}") from first_error
        parsed = None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                parsed = pd.to_datetime(value, format=fmt, utc=True, errors="raise")
                break
            except (TypeError, ValueError, OverflowError):
                continue
        if parsed is None:
            raise ValueError(f"invalid timestamp {value!r}") from first_error
    if pd.isna(parsed):
        raise ValueError(f"invalid timestamp {value!r}")
    return parsed.to_pydatetime()


def _coerce_number(value: Any, field: str, default: int | None) -> int | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    try:
        numeric = pd.to_numeric(value, errors="raise")
        number = float(numeric)
        if not math.isfinite(number) or not number.is_integer():
            raise ValueError(f"{field} must be a finite whole number")
        return int(number)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid {field}: {value!r}") from exc


def normalize_log_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one generic security event, raising for invalid row values."""
    ts_value = _lookup(raw, "timestamp", "time", "UtcTime", "Timestamp")
    ts = parse_timestamp(ts_value)
    user_id = _lookup(raw, "user_id", "username", "User")
    device_id = _lookup(raw, "device_id", "host_id", "Computer")
    src_ip = _lookup(raw, "source_ip", "src_ip", "SourceIp", "Source IP")
    dst_ip = _lookup(raw, "destination_ip", "dst_ip", "DestinationIp", "Destination IP")

    event_type = str(_lookup(raw, "event_type", "action", "EventID") or "generic_event")
    category = _lookup(raw, "event_category", "category")
    if not category:
        if "login" in event_type.lower() or "auth" in event_type.lower():
            category = "auth"
        elif "process" in event_type.lower() or _lookup(raw, "process_name", "Image"):
            category = "endpoint"
        elif "flow" in event_type.lower() or _lookup(raw, "source_port", "Source Port") or dst_ip:
            category = "network"
        else:
            category = "access"

    source_port = _coerce_number(_lookup(raw, "source_port", "src_port", "Source Port"), "source_port", None)
    destination_port = _coerce_number(
        _lookup(raw, "destination_port", "dst_port", "Destination Port"), "destination_port", None
    )
    byte_value = _lookup(raw, "bytes_transferred", "bytes", "Bytes")
    bytes_transferred = _coerce_number(byte_value, "bytes_transferred", 0)
    return {
        "event_id": str(_lookup(raw, "event_id") or f"evt_{uuid.uuid4().hex[:12]}"),
        "timestamp": ts,
        "user_id": str(user_id) if user_id is not None else None,
        "device_id": str(device_id) if device_id is not None else None,
        "source_ip": str(src_ip) if src_ip is not None else None,
        "destination_ip": str(dst_ip) if dst_ip is not None else None,
        "source_port": source_port,
        "destination_port": destination_port,
        "event_category": str(category),
        "event_type": event_type,
        "status": str(_lookup(raw, "status") or "success"),
        "location": str(_lookup(raw, "location") or "Unknown"),
        "privilege_level": str(_lookup(raw, "privilege_level") or "standard"),
        "bytes_transferred": bytes_transferred,
        "process_name": _lookup(raw, "process_name", "Image"),
        "command_line": _lookup(raw, "command_line", "CommandLine"),
        "raw_payload": {str(key).strip(): value for key, value in raw.items() if key is not None},
        "dataset": _lookup(raw, "dataset"),
        "scenario": _lookup(raw, "scenario"),
    }


def _decode_upload(file_bytes: bytes) -> str:
    try:
        return file_bytes.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Upload is not valid UTF-8 text.") from exc


def _upload_records(file_name: str, text: str) -> tuple[list[str], Iterable[tuple[int, Dict[str, Any]]]]:
    extension = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if extension == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}.") from exc
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            raise ValueError("JSON upload must contain an object or an array of objects.")
        return [], ((index, row) for index, row in enumerate(payload, start=1))
    if extension != "csv":
        raise ValueError("Only .csv and .json uploads are accepted.")
    stream = io.StringIO(text, newline="")
    reader = csv.DictReader(stream)
    if not reader.fieldnames:
        raise ValueError("CSV upload is missing a header row.")
    headers = [str(header).strip() if header is not None else "" for header in reader.fieldnames]
    if any(not header for header in headers):
        raise ValueError("CSV header names cannot be empty.")
    if len({header.casefold() for header in headers}) != len(headers):
        raise ValueError("CSV contains duplicate header names after trimming whitespace.")

    def rows():
        for row_number, values in enumerate(reader, start=2):
            cleaned = {}
            for key, value in values.items():
                if key is not None:
                    cleaned[str(key).strip()] = value
            yield row_number, cleaned

    return headers, rows()


def count_upload_rows(file_name: str, file_bytes: bytes) -> int:
    """Count data rows for deciding whether to use the background upload worker."""
    text = _decode_upload(file_bytes)
    _headers, records = _upload_records(file_name, text)
    return sum(1 for _ in records)


def _flow_features(raw: Dict[str, Any], feature_names: list[str]) -> Dict[str, float]:
    indexed = {str(key).strip(): value for key, value in raw.items()}
    values = {}
    for name in feature_names:
        if name not in indexed:
            raise ValueError(f"missing CICIDS feature {name!r}")
        value = indexed[name]
        try:
            numeric = float(pd.to_numeric(value, errors="raise"))
            if not math.isfinite(numeric):
                raise ValueError("must be finite")
            values[name] = numeric
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid CICIDS feature {name!r}: {value!r}") from exc
    return values


def _get_configured_bundle(detect: bool):
    from app.detection.engine import load_model_bundle, MODEL_BUNDLE_PATH

    if not detect and not MODEL_BUNDLE_PATH.is_file():
        return None
    return load_model_bundle()


def _lookup_existing_hashes(db: Session, hashes: set[str]) -> set[str]:
    if not hashes:
        return set()
    # Backfill any pre-migration rows that were not seen by startup yet.
    for event in db.query(SecurityEvent).filter(SecurityEvent.dedup_hash.is_(None)).yield_per(1000):
        event.dedup_hash = stable_event_hash(event)
    db.flush()
    existing = set()
    values = list(hashes)
    for start in range(0, len(values), 500):
        chunk = values[start:start + 500]
        existing.update(
            value for (value,) in db.query(SecurityEvent.dedup_hash)
            .filter(SecurityEvent.dedup_hash.in_(chunk)).all()
        )
    return existing


def _ensure_foreign_key_rows(db: Session, events: list[SecurityEvent]) -> None:
    user_ids = {event.user_id for event in events if event.user_id}
    device_ids = {event.device_id for event in events if event.device_id}
    existing_users = {
        value for (value,) in db.query(User.user_id).filter(User.user_id.in_(user_ids)).all()
    } if user_ids else set()
    existing_devices = {
        value for (value,) in db.query(Device.device_id).filter(Device.device_id.in_(device_ids)).all()
    } if device_ids else set()
    db.add_all([
        User(user_id=value, username=value, role="employee", privilege_level="standard")
        for value in sorted(user_ids - existing_users)
    ])
    db.add_all([
        Device(device_id=value, hostname=value, os="Unknown", device_type="workstation")
        for value in sorted(device_ids - existing_devices)
    ])


def process_uploaded_log_file(
    file_name: str,
    file_bytes: bytes,
    db: Session,
    detect: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> Dict[str, Any]:
    """Validate rows independently, de-duplicate, and persist in batches."""
    if not file_name or not file_name.lower().endswith((".csv", ".json")):
        raise ValueError("Only .csv and .json uploads are accepted.")
    limit = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if len(file_bytes) > limit:
        raise ValueError(f"Upload exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB limit.")
    text = _decode_upload(file_bytes)
    headers, source_records = _upload_records(file_name, text)
    bundle = _get_configured_bundle(detect)
    feature_names = list(bundle["feature_names"]) if bundle else []
    is_cicids_flow = bool(feature_names) and set(feature_names).issubset(set(headers))

    candidates = []
    rejected_examples = []
    rejected_count = 0
    rows_read = 0
    for row_number, raw in source_records:
        rows_read += 1
        try:
            if not isinstance(raw, dict):
                raise ValueError("row must be a JSON object or CSV record")
            event_data = normalize_log_record(raw)
            flow = None
            if is_cicids_flow:
                flow = _flow_features(raw, feature_names)
                event_data["event_category"] = "network"
                event_data["event_type"] = str(_lookup(raw, "event_type") or "cicids2017_flow")
                event_data["dataset"] = event_data["dataset"] or "cicids2017_upload"
                event_data["raw_payload"] = {
                    "cicids_features": flow,
                    "source_row": raw,
                }
            event_hash = stable_event_hash(event_data)
            candidates.append({
                "row_number": row_number,
                "event_data": event_data,
                "flow": flow,
                "dedup_hash": event_hash,
            })
        except (TypeError, ValueError, OverflowError) as exc:
            rejected_count += 1
            if len(rejected_examples) < 20:
                rejected_examples.append({"row_number": row_number, "reason": str(exc)})
        if progress_callback and (rows_read % 250 == 0):
            progress_callback({"rows_read": rows_read, "rejected": rejected_count})

    existing_hashes = _lookup_existing_hashes(db, {row["dedup_hash"] for row in candidates})
    seen_hashes = set()
    accepted = []
    duplicate_count = 0
    for row in candidates:
        fingerprint = row["dedup_hash"]
        if fingerprint in existing_hashes or fingerprint in seen_hashes:
            duplicate_count += 1
            continue
        seen_hashes.add(fingerprint)
        accepted.append(row)

    candidate_ids = {row["event_data"]["event_id"] for row in accepted}
    existing_event_ids = {
        value for (value,) in db.query(SecurityEvent.event_id)
        .filter(SecurityEvent.event_id.in_(candidate_ids)).all()
    } if candidate_ids else set()
    seen_event_ids = set(existing_event_ids)
    event_rows = []
    flow_rows = []
    for row in accepted:
        event_data = row["event_data"]
        if event_data["event_id"] in seen_event_ids:
            event_data["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
        seen_event_ids.add(event_data["event_id"])
        event = SecurityEvent(**event_data, dedup_hash=row["dedup_hash"])
        event_rows.append(event)
        if is_cicids_flow:
            flow_rows.append(row["flow"])

    _ensure_foreign_key_rows(db, event_rows)
    db.add_all(event_rows)
    db.flush()

    detection_counts = None
    if detect:
        if is_cicids_flow and event_rows:
            from app.detection.engine import persist_scored_batch, score_batch

            predictions = score_batch(pd.DataFrame(flow_rows, columns=feature_names), bundle, events=event_rows)
            detection_counts = persist_scored_batch(event_rows, predictions, bundle, db)
        else:
            detection_counts = {"not_scored": len(event_rows)} if event_rows else {}

    db.commit()
    category_counts = dict(Counter(event.event_category for event in event_rows))
    if progress_callback:
        progress_callback({
            "rows_read": rows_read,
            "inserted": len(event_rows),
            "duplicates": duplicate_count,
            "rejected": rejected_count,
        })
    report = {
        "status": "success",
        "file_name": file_name,
        "rows_read": rows_read,
        "inserted": len(event_rows),
        "duplicates": duplicate_count,
        "rejected": {"count": rejected_count, "examples": rejected_examples},
        "by_category": category_counts,
        "message": f"Inserted {len(event_rows)} of {rows_read} rows.",
    }
    if detect:
        report["detection_counts"] = detection_counts
    return report
