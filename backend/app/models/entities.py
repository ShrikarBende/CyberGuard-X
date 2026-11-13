"""
Database models for Enterprise CyberGuard X.
Implements the 10 core tables:
1. users
2. devices
3. security_events
4. detection_results
5. incidents
6. incident_events
7. risk_scores
8. investigation_notes
9. mitre_techniques
10. analyst_activity
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    DateTime,
    Boolean,
    Text,
    JSON,
    ForeignKey,
    Index
)
from sqlalchemy.orm import relationship
from app.database.session import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    user_id = Column(String(128), primary_key=True, index=True)
    username = Column(String(128), nullable=False)
    email = Column(String(128), nullable=True)
    department = Column(String(64), nullable=True)
    role = Column(String(64), default="employee")
    privilege_level = Column(String(32), default="standard")
    risk_score = Column(Float, default=0.0)
    baseline_activity = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    events = relationship("SecurityEvent", back_populates="user")
    incidents = relationship("Incident", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String(128), primary_key=True, index=True)
    hostname = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    mac_address = Column(String(64), nullable=True)
    os = Column(String(64), nullable=True)
    device_type = Column(String(32), default="workstation")  # workstation, server, gateway
    agent_version = Column(String(32), default="2.0.0")
    risk_score = Column(Float, default=0.0)
    is_isolated = Column(Boolean, default=False)
    last_seen = Column(DateTime(timezone=True), default=utc_now)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    # Relationships
    events = relationship("SecurityEvent", back_populates="device")
    incidents = relationship("Incident", back_populates="device")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    event_id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    user_id = Column(String(128), ForeignKey("users.user_id"), nullable=True, index=True)
    device_id = Column(String(128), ForeignKey("devices.device_id"), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    event_category = Column(String(32), nullable=False, index=True)  # auth, endpoint, network, access
    event_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="success")  # success, failure, blocked
    privilege_level = Column(String(32), nullable=True)
    process_name = Column(String(256), nullable=True)
    command_line = Column(Text, nullable=True)
    bytes_transferred = Column(Integer, default=0)
    location = Column(String(128), nullable=True)
    raw_payload = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    # Relationships
    user = relationship("User", back_populates="events")
    device = relationship("Device", back_populates="events")
    detection_result = relationship("DetectionResult", back_populates="event", uselist=False)
    incident_associations = relationship("IncidentEvent", back_populates="event")


class DetectionResult(Base):
    __tablename__ = "detection_results"

    detection_id = Column(String(128), primary_key=True, index=True)
    event_id = Column(String(128), ForeignKey("security_events.event_id"), nullable=False, unique=True, index=True)
    verdict = Column(String(32), nullable=False, default="BENIGN")  # BENIGN, KNOWN_THREAT, UNKNOWN_NOVEL_THREAT, SUSPICIOUS
    predicted_class = Column(String(64), nullable=True)  # e.g., Brute Force, Port Scan, Ransomware, Unknown
    confidence = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    open_set_distance = Column(Float, default=0.0)  # Distance in latent space
    reconstruction_error = Column(Float, default=0.0)
    layer = Column(String(32), nullable=False)  # user, endpoint, network
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    # Relationships
    event = relationship("SecurityEvent", back_populates="detection_result")


class Incident(Base):
    __tablename__ = "incidents"

    incident_id = Column(String(128), primary_key=True, index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(32), nullable=False, default="OPEN")  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    threat_classification = Column(String(64), nullable=False, default="UNKNOWN_NOVEL_THREAT")
    overall_risk_score = Column(Float, nullable=False, default=50.0)  # 0 to 100
    user_id = Column(String(128), ForeignKey("users.user_id"), nullable=True)
    device_id = Column(String(128), ForeignKey("devices.device_id"), nullable=True)
    attack_sequence = Column(JSON, nullable=True)  # Kill chain stages list
    evidence = Column(JSON, nullable=True)
    first_detected_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    # Relationships
    user = relationship("User", back_populates="incidents")
    device = relationship("Device", back_populates="incidents")
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    risk_score_detail = relationship("RiskScore", back_populates="incident", uselist=False, cascade="all, delete-orphan")
    notes = relationship("InvestigationNote", back_populates="incident", cascade="all, delete-orphan")
    mitre_mappings = relationship("MitreTechnique", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(128), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    event_id = Column(String(128), ForeignKey("security_events.event_id"), nullable=False, index=True)
    stage = Column(String(64), nullable=True)  # initial_access, execution, lateral_movement, exfiltration
    order = Column(Integer, default=0)

    # Relationships
    incident = relationship("Incident", back_populates="events")
    event = relationship("SecurityEvent", back_populates="incident_associations")


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(128), ForeignKey("incidents.incident_id"), nullable=False, unique=True, index=True)
    score = Column(Float, nullable=False)  # 0 to 100
    category = Column(String(32), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    user_risk_component = Column(Float, default=0.0)
    endpoint_risk_component = Column(Float, default=0.0)
    network_risk_component = Column(Float, default=0.0)
    anomaly_factor = Column(Float, default=0.0)
    correlation_multiplier = Column(Float, default=1.0)
    top_contributing_features = Column(JSON, nullable=True)  # SHAP feature contributions
    explanation_summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    incident = relationship("Incident", back_populates="risk_score_detail")


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"

    note_id = Column(String(128), primary_key=True, index=True)
    incident_id = Column(String(128), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    author = Column(String(64), nullable=False, default="SOC Analyst")
    content = Column(Text, nullable=False)
    is_ai_generated = Column(Boolean, default=False)
    citations = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    incident = relationship("Incident", back_populates="notes")


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(128), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    tactic = Column(String(64), nullable=False)
    technique_id = Column(String(32), nullable=False, index=True)
    technique_name = Column(String(128), nullable=False)
    confidence = Column(Float, default=0.85)
    evidence_predicate = Column(JSON, nullable=True)  # Concrete features that satisfied rule
    is_verified = Column(Boolean, default=True)

    incident = relationship("Incident", back_populates="mitre_mappings")


class AnalystActivity(Base):
    __tablename__ = "analyst_activity"

    activity_id = Column(String(128), primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, index=True)
    analyst_name = Column(String(64), nullable=False)
    action_type = Column(String(64), nullable=False)  # status_update, note_added, host_isolated, model_trained
    target_entity = Column(String(64), nullable=True)
    target_id = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True)


Index("idx_security_event_cat_time", SecurityEvent.event_category, SecurityEvent.timestamp)
Index("idx_incident_severity_status", Incident.severity, Incident.status)

