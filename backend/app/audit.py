"""Audit trail helpers for analyst actions."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.entities import AnalystActivity


def record_analyst_activity(
    db: Session,
    analyst_name: str,
    action_type: str,
    target_entity: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AnalystActivity:
    activity = AnalystActivity(
        activity_id=f"activity_{uuid.uuid4().hex}",
        timestamp=datetime.now(timezone.utc),
        analyst_name=(analyst_name or "unknown")[:64],
        action_type=action_type[:64],
        target_entity=target_entity[:64] if target_entity else None,
        target_id=target_id[:128] if target_id else None,
        details=details or {},
    )
    db.add(activity)
    return activity
