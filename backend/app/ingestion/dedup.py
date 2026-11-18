"""Stable event fingerprints used to de-duplicate uploaded telemetry."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, date, timezone
from typing import Any


DEDUP_FIELDS = (
    "timestamp", "user_id", "device_id", "source_ip", "destination_ip",
    "source_port", "destination_port", "event_category", "event_type", "status",
    "privilege_level", "process_name", "command_line", "bytes_transferred",
    "location", "raw_payload",
)


def stable_event_hash(event: Any) -> str:
    """Hash normalized event key fields, excluding generated IDs and import labels."""
    values = {}
    for name in DEDUP_FIELDS:
        value = event.get(name) if isinstance(event, dict) else getattr(event, name, None)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            else:
                value = value.astimezone(timezone.utc)
            value = value.isoformat()
        elif isinstance(value, date):
            value = value.isoformat()
        values[name] = value
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
