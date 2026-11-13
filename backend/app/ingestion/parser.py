"""
Data Ingestion Module:
Handles CSV and JSON log uploads, schema validation, and normalization.
Supports:
1. Authentication logs
2. User activity logs
3. Endpoint/process activity logs
4. Network connection logs
5. Device access logs
6. Privilege and access-control logs
"""
from typing import Dict, Any, List
from datetime import datetime, timezone
import io
import csv
import json
import uuid
from sqlalchemy.orm import Session
from app.models.entities import SecurityEvent, User, Device


def parse_timestamp(ts: Any) -> datetime:
    """Parse multiple timestamp formats into UTC datetime."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(ts, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def normalize_log_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize log record into standard schema."""
    ts = parse_timestamp(raw.get("timestamp") or raw.get("time") or raw.get("UtcTime"))
    user_id = raw.get("user_id") or raw.get("username") or raw.get("User")
    device_id = raw.get("device_id") or raw.get("host_id") or raw.get("Computer")
    src_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("SourceIp")
    dst_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("DestinationIp")

    event_type = str(raw.get("event_type") or raw.get("action") or raw.get("EventID") or "generic_event")

    # Determine category
    category = raw.get("event_category") or raw.get("category")
    if not category:
        if "login" in event_type.lower() or "auth" in event_type.lower():
            category = "auth"
        elif "process" in event_type.lower() or raw.get("process_name"):
            category = "endpoint"
        elif "flow" in event_type.lower() or raw.get("source_port") or dst_ip:
            category = "network"
        else:
            category = "access"

    return {
        "event_id": str(raw.get("event_id") or f"evt_{uuid.uuid4().hex[:12]}"),
        "timestamp": ts,
        "user_id": user_id,
        "device_id": device_id,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_port": int(raw.get("source_port") or 0) or None,
        "destination_port": int(raw.get("destination_port") or 0) or None,
        "event_category": category,
        "event_type": event_type,
        "status": raw.get("status", "success"),
        "location": raw.get("location", "Unknown"),
        "privilege_level": raw.get("privilege_level", "standard"),
        "bytes_transferred": int(raw.get("bytes_transferred") or raw.get("bytes") or 0),
        "process_name": raw.get("process_name") or raw.get("Image"),
        "command_line": raw.get("command_line") or raw.get("CommandLine"),
        "raw_payload": raw
    }


def process_uploaded_log_file(file_name: str, file_bytes: bytes, db: Session) -> Dict[str, Any]:
    """Parse CSV or JSON file and insert normalized events into database."""
    content_str = file_bytes.decode("utf-8", errors="ignore")
    records = []

    if file_name.endswith(".json"):
        data = json.loads(content_str)
        if isinstance(data, dict):
            data = [data]
        records = [normalize_log_record(r) for r in data]
    else:  # Assume CSV
        reader = csv.DictReader(io.StringIO(content_str))
        records = [normalize_log_record(row) for row in reader]

    inserted_count = 0
    for r in records:
        evt = SecurityEvent(**r)
        db.add(evt)
        inserted_count += 1

    db.commit()

    return {
        "status": "success",
        "file_name": file_name,
        "records_processed": inserted_count,
        "message": f"Successfully ingested and normalized {inserted_count} security events."
    }

