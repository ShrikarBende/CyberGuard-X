"""
Synthetic Enterprise Security-Log Generator:
Implements Section 4 and Section 13:
Generates realistic multi-layer enterprise log scenarios:
1. Normal employee activity
2. Brute-force attempts
3. Suspicious login / Impossible travel
4. Account takeover & Privilege escalation
5. Suspicious process execution (LOLBAS PowerShell)
6. Port scanning & Network reconnaissance
7. Lateral movement (SMB admin shares)
8. Abnormal data transfer & Exfiltration
9. Previously unseen novel zero-day threats
"""
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
import random
import uuid
from sqlalchemy.orm import Session
from app.models.entities import User, Device, SecurityEvent, Incident, RiskScore, MitreTechnique, DetectionResult

USERS_DATA = [
    ("usr_alice", "Alice Vance", "Engineering", "DevOps Lead", "admin"),
    ("usr_bob", "Bob Stone", "Finance", "Senior Accountant", "standard"),
    ("usr_carol", "Carol Danvers", "Security", "SOC Analyst", "admin"),
    ("usr_david", "David Miller", "Executive", "VP Finance", "executive"),
    ("usr_eve", "Eve Adams", "Engineering", "Backend Engineer", "standard"),
    ("usr_frank", "Frank Castle", "IT Support", "Systems Admin", "admin"),
]

DEVICES_DATA = [
    ("dev_ws_alice", "ws-alice.corp.local", "10.0.1.15", "Windows 11 Enterprise", "workstation"),
    ("dev_fin_srv", "fin-srv-02.corp.local", "10.0.2.44", "Ubuntu 22.04 LTS", "server"),
    ("dev_dc01", "dc-master.corp.local", "10.0.0.1", "Windows Server 2022", "server"),
    ("dev_ws_david", "exec-laptop-01.corp.local", "10.0.0.99", "macOS Sonoma 14.5", "workstation"),
    ("dev_sec_ops", "sec-ops-01.corp.local", "10.0.4.10", "Fedora 40 Workstation", "workstation"),
]


def seed_enterprise_baseline(db: Session):
    """Seed initial corporate users, devices, events, detections, and multi-stage incidents."""
    # Check if already seeded
    if db.query(User).count() > 0:
        return

    now = datetime.now(timezone.utc)

    # 1. Users
    for uid, name, dept, role, priv in USERS_DATA:
        user = User(
            user_id=uid,
            username=name,
            email=f"{uid}@enterprise.corp",
            department=dept,
            role=role,
            privilege_level=priv,
            risk_score=75.0 if uid in ("usr_alice", "usr_david") else 20.0
        )
        db.add(user)

    # 2. Devices
    for did, hname, ip, os_name, dtype in DEVICES_DATA:
        device = Device(
            device_id=did,
            hostname=hname,
            ip_address=ip,
            os=os_name,
            device_type=dtype,
            risk_score=85.0 if did in ("dev_ws_alice", "dev_dc01") else 15.0,
            is_isolated=(did == "dev_dc01")
        )
        db.add(device)

    # 3. Baseline Normal & Attack Events
    scenarios = [
        # Scenario 1: Normal Login & Work Activity
        {
            "user": "usr_carol",
            "device": "dev_sec_ops",
            "cat": "auth",
            "type": "user_login",
            "status": "success",
            "src": "10.0.4.10",
            "dst": "10.0.0.1",
            "verdict": "BENIGN",
            "class": "Benign",
            "risk": 10.0,
            "min_ago": 55
        },
        # Scenario 2: Brute Force Attempt
        {
            "user": "usr_bob",
            "device": "dev_fin_srv",
            "cat": "auth",
            "type": "failed_login_burst",
            "status": "failure",
            "src": "198.51.100.22",
            "dst": "10.0.2.44",
            "verdict": "KNOWN_THREAT",
            "class": "Brute Force",
            "risk": 78.0,
            "min_ago": 40,
            "tactic": "Credential Access",
            "tech": "T1110",
            "tech_name": "Brute Force"
        },
        # Scenario 3: Impossible Travel Anomaly
        {
            "user": "usr_bob",
            "device": "dev_fin_srv",
            "cat": "auth",
            "type": "impossible_travel_login",
            "status": "success",
            "src": "203.0.113.88",
            "dst": "10.0.2.44",
            "verdict": "KNOWN_THREAT",
            "class": "Identity Compromise",
            "risk": 82.0,
            "min_ago": 28,
            "tactic": "Defense Evasion",
            "tech": "T1078",
            "tech_name": "Valid Accounts"
        },
        # Scenario 4: Suspicious Process (LOLBAS PowerShell)
        {
            "user": "usr_alice",
            "device": "dev_ws_alice",
            "cat": "endpoint",
            "type": "process_create",
            "status": "success",
            "src": "10.0.1.15",
            "dst": "10.0.0.1",
            "proc": "powershell.exe",
            "cmd": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
            "verdict": "KNOWN_THREAT",
            "class": "LOLBAS Execution",
            "risk": 89.0,
            "min_ago": 18,
            "tactic": "Execution",
            "tech": "T1059.001",
            "tech_name": "PowerShell"
        },
        # Scenario 5: Lateral Movement via SMB
        {
            "user": "usr_alice",
            "device": "dev_ws_alice",
            "cat": "network",
            "type": "smb_admin_access",
            "status": "success",
            "src": "10.0.1.15",
            "dst": "10.0.0.1",
            "bytes": 45000000,
            "verdict": "KNOWN_THREAT",
            "class": "Lateral Movement",
            "risk": 91.0,
            "min_ago": 10,
            "tactic": "Lateral Movement",
            "tech": "T1021.002",
            "tech_name": "Remote Services: SMB"
        },
        # Scenario 6: Previously Unseen Novel Threat (Open-Set Zero-Day C2 & Exfil)
        {
            "user": "usr_david",
            "device": "dev_dc01",
            "cat": "network",
            "type": "novel_doh_tunnel_exfil",
            "status": "blocked",
            "src": "10.0.0.1",
            "dst": "198.51.100.99",
            "bytes": 128000000,
            "verdict": "UNKNOWN_NOVEL_THREAT",
            "class": "Unknown / Novel Attack Pattern",
            "risk": 96.5,
            "min_ago": 4,
            "tactic": "Exfiltration",
            "tech": "T1048",
            "tech_name": "Exfiltration Over Alternative Protocol"
        }
    ]

    for item in scenarios:
        evt_id = f"evt_{uuid.uuid4().hex[:12]}"
        evt_time = now - timedelta(minutes=item["min_ago"])
        evt = SecurityEvent(
            event_id=evt_id,
            timestamp=evt_time,
            user_id=item["user"],
            device_id=item["device"],
            source_ip=item["src"],
            destination_ip=item["dst"],
            event_category=item["cat"],
            event_type=item["type"],
            status=item["status"],
            process_name=item.get("proc"),
            command_line=item.get("cmd"),
            bytes_transferred=item.get("bytes", 1500)
        )
        db.add(evt)

        # Detection Result
        det_id = f"det_{uuid.uuid4().hex[:12]}"
        is_unknown = (item["verdict"] == "UNKNOWN_NOVEL_THREAT")
        det = DetectionResult(
            detection_id=det_id,
            event_id=evt_id,
            verdict=item["verdict"],
            predicted_class=item["class"],
            confidence=0.94 if not is_unknown else 0.45,
            anomaly_score=0.96 if is_unknown else (0.85 if item["verdict"] != "BENIGN" else 0.05),
            open_set_distance=6.85 if is_unknown else (2.10 if item["verdict"] != "BENIGN" else 0.85),
            reconstruction_error=0.34 if is_unknown else 0.04,
            layer=item["cat"]
        )
        db.add(det)

        # If it's a threat, create an Incident
        if item["verdict"] != "BENIGN":
            inc_id = f"inc_{uuid.uuid4().hex[:12]}"
            inc = Incident(
                incident_id=inc_id,
                title=f"{item['verdict'].replace('_', ' ')}: {item['class']}",
                description=f"Automated threat detection in {item['cat']} layer targeting {item['device']}.",
                severity="CRITICAL" if item["risk"] >= 85.0 else "HIGH",
                status="OPEN",
                threat_classification=item["verdict"],
                overall_risk_score=item["risk"],
                user_id=item["user"],
                device_id=item["device"],
                first_detected_at=evt_time,
                last_updated_at=now
            )
            db.add(inc)

            # Risk Score
            db.add(RiskScore(
                incident_id=inc_id,
                score=item["risk"],
                category="CRITICAL" if item["risk"] >= 85.0 else "HIGH",
                user_risk_component=0.85 if item["cat"] == "auth" else 0.2,
                endpoint_risk_component=0.92 if item["cat"] == "endpoint" else 0.2,
                network_risk_component=0.95 if item["cat"] == "network" else 0.2,
                anomaly_factor=det.anomaly_score,
                correlation_multiplier=1.25,
                top_contributing_features=[
                    {"feature": "latent_space_distance", "importance": 0.44, "contribution": "open_set_anomaly"},
                    {"feature": "reconstruction_residual", "importance": 0.36, "contribution": "autoencoder_error"},
                    {"feature": "outbound_byte_volume", "importance": 0.31, "contribution": "data_transfer"}
                ],
                explanation_summary=f"Event exhibited significant behavioral drift. Open-set distance is {det.open_set_distance}."
            ))

            # MITRE
            if "tactic" in item:
                db.add(MitreTechnique(
                    incident_id=inc_id,
                    tactic=item["tactic"],
                    technique_id=item["tech"],
                    technique_name=item["tech_name"],
                    confidence=0.91,
                    is_verified=True
                ))

    db.commit()
    print("Baseline enterprise security logs and incidents initialized successfully.")

