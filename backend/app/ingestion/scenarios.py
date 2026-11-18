"""Rule-correlation demo scenarios; generation creates event rows only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid


def generate_demo_events(now: datetime | None = None) -> list[dict]:
    """Return labelled synthetic event dictionaries for four fixed scenarios."""
    anchor = now or datetime.now(timezone.utc)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    anchor = anchor.astimezone(timezone.utc)
    day = anchor.date()
    events: list[dict] = []

    def add(scenario: str, at: datetime, user: str, device: str, source_ip: str,
            category: str, event_type: str, **fields) -> None:
        events.append({
            "event_id": f"demo_{uuid.uuid4().hex[:16]}",
            "timestamp": at,
            "user_id": user,
            "device_id": device,
            "source_ip": source_ip,
            "event_category": category,
            "event_type": event_type,
            "status": "success",
            "privilege_level": "standard",
            "bytes_transferred": 0,
            "location": "Synthetic demo",
            "dataset": "synthetic_demo",
            "scenario": scenario,
            **fields,
        })

    def time_at(hour: int, minute: int, *, days_ago: int = 0) -> datetime:
        return datetime.combine(day - timedelta(days=days_ago), datetime.min.time(), tzinfo=timezone.utc).replace(
            hour=hour, minute=minute
        )

    # (a) Multi-stage takeover: baseline success, failure burst, unusual login,
    # privilege change, encoded script, rare outbound port, and external transfer.
    takeover_user, takeover_device = "demo_takeover_user", "demo_takeover_device"
    add("multi_stage_takeover", time_at(10, 0, days_ago=2), takeover_user, takeover_device,
        "1.1.1.1", "auth", "login_success", raw_payload={"source": "baseline_login"})
    for minute in (0, 2, 4, 6, 8):
        add("multi_stage_takeover", time_at(2, minute), takeover_user, takeover_device,
            "8.8.4.4", "auth", "login_failure", status="failure")
    add("multi_stage_takeover", time_at(2, 30), takeover_user, takeover_device,
        "8.8.4.4", "auth", "login_success")
    add("multi_stage_takeover", time_at(2, 35), takeover_user, takeover_device,
        "8.8.4.4", "access", "privilege_change", privilege_level="admin",
        raw_payload={"previous_privilege": "standard", "new_privilege": "admin"})
    add("multi_stage_takeover", time_at(2, 38), takeover_user, takeover_device,
        "8.8.4.4", "endpoint", "process_start", process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA", raw_payload={"parent_process": "winword.exe"})
    add("multi_stage_takeover", time_at(2, 42), takeover_user, takeover_device,
        "8.8.4.4", "network", "outbound_connection", destination_ip="8.8.8.8",
        destination_port=4444)
    add("multi_stage_takeover", time_at(2, 50), takeover_user, takeover_device,
        "8.8.4.4", "network", "data_transfer", destination_ip="8.8.8.8",
        destination_port=443, bytes_transferred=150 * 1024 * 1024)

    # (b) Password guessing with no successful login or post-authentication activity.
    brute_user, brute_device = "demo_bruteforce_user", "demo_bruteforce_device"
    for minute in (0, 2, 4, 6, 8):
        add("brute_force_only", time_at(14, minute), brute_user, brute_device,
            "198.51.100.24", "auth", "login_failure", status="failure")

    # (c) Benign admin maintenance: two rule indicators, but only two indicator types.
    add("benign_admin", time_at(10, 15), "demo_admin", "demo_admin_device",
        "10.20.30.40", "access", "privilege_change", privilege_level="admin",
        raw_payload={"previous_privilege": "standard", "new_privilege": "admin", "change_ticket": "CHG-DEMO-12"})
    add("benign_admin", time_at(10, 30), "demo_admin", "demo_admin_device",
        "10.20.30.40", "network", "backup_transfer", destination_ip="10.20.30.50",
        destination_port=445, bytes_transferred=180 * 1024 * 1024,
        raw_payload={"transfer_purpose": "scheduled backup"})

    # (d) Ordinary daytime work with no configured rule indicators.
    normal_user, normal_device = "demo_employee", "demo_employee_device"
    add("normal_employee_day", time_at(9, 0), normal_user, normal_device,
        "10.40.0.25", "auth", "login_success")
    add("normal_employee_day", time_at(9, 10), normal_user, normal_device,
        "10.40.0.25", "endpoint", "process_start", process_name="outlook.exe")
    add("normal_employee_day", time_at(9, 20), normal_user, normal_device,
        "10.40.0.25", "network", "outbound_connection", destination_ip="93.184.216.34",
        destination_port=443, bytes_transferred=2 * 1024 * 1024)
    add("normal_employee_day", time_at(11, 0), normal_user, normal_device,
        "10.40.0.25", "access", "file_read", raw_payload={"resource": "team calendar"})

    return sorted(events, key=lambda event: event["timestamp"])
