"""
Pydantic v2 schemas for Enterprise CyberGuard X.
"""
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator


# -------------------------------------------------------------------
# Security Event Schemas
# -------------------------------------------------------------------
class SecurityEventCreate(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    device_id: Optional[str] = None
    event_type: str
    event_category: str = "endpoint"  # auth, endpoint, network, access
    status: str = "success"
    location: Optional[str] = "Unknown"
    privilege_level: Optional[str] = "standard"
    bytes_transferred: Optional[int] = 0
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None
    dataset: Optional[str] = None
    scenario: Optional[str] = None


class SecurityEventResponse(SecurityEventCreate):
    event_id: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# Detection Result Schemas
# -------------------------------------------------------------------
class DetectionResultResponse(BaseModel):
    detection_id: str
    event_id: str
    verdict: str  # BENIGN, KNOWN_THREAT, UNKNOWN_CANDIDATE
    predicted_class: Optional[str] = None
    score: Optional[float] = None
    probability: Optional[float] = None
    attack_probability: Optional[float] = None
    open_set_distance: Optional[float] = None
    reconstruction_error: Optional[float] = None
    model_version: Optional[str] = None
    tau: Optional[float] = None
    layer: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# Incident & Risk Schemas
# -------------------------------------------------------------------
class MitreTechniqueResponse(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    confidence: Union[float, str]
    evidence_predicate: Optional[Dict[str, Any]] = None
    is_verified: bool = False

    model_config = ConfigDict(from_attributes=True)


class InvestigationNoteCreate(BaseModel):
    content: str
    author: Optional[str] = "SOC Analyst"
    feedback_label: Optional[str] = None

    @field_validator("feedback_label")
    @classmethod
    def validate_feedback_label(cls, value):
        if value is not None and value not in {"CONFIRMED", "FALSE_POSITIVE"}:
            raise ValueError("feedback_label must be CONFIRMED or FALSE_POSITIVE")
        return value


class InvestigationNoteResponse(BaseModel):
    note_id: str
    incident_id: str
    author: str
    content: str
    is_ai_generated: bool
    citations: Optional[List[str]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskScoreResponse(BaseModel):
    score: float
    category: str
    user_risk_component: Optional[float] = None
    endpoint_risk_component: Optional[float] = None
    network_risk_component: Optional[float] = None
    anomaly_factor: Optional[float] = None
    correlation_multiplier: Optional[float] = None
    top_contributing_features: Optional[List[Dict[str, Any]]] = None
    explanation_summary: Optional[str] = None
    risk_breakdown: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    threat_classification: str
    overall_risk_score: float
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    attack_sequence: Optional[List[Dict[str, Any]]] = None
    evidence: Optional[Dict[str, Any]] = None
    flow_count: int = 1
    first_detected_at: datetime
    last_updated_at: datetime
    risk_score_detail: Optional[RiskScoreResponse] = None
    mitre_mappings: List[MitreTechniqueResponse] = []
    notes: List[InvestigationNoteResponse] = []

    model_config = ConfigDict(from_attributes=True)


# -------------------------------------------------------------------
# Dashboard Stats & Threats Schemas
# -------------------------------------------------------------------
class DashboardStatsResponse(BaseModel):
    total_events: int
    total_detections: int
    total_threats: int
    known_threats: int
    unknown_candidates: int
    critical_incidents: int
    normal_events: int
    threat_distribution: List[Dict[str, Any]]
    risk_trend: List[Dict[str, Any]]
    layer_detection_stats: Dict[str, int]
    system_status: str = "operational"


# -------------------------------------------------------------------
# RAG Chat Schemas
# -------------------------------------------------------------------
class RAGChatRequest(BaseModel):
    incident_id: Optional[str] = None
    query: str


class RAGChatResponse(BaseModel):
    answer: str
    mode: str
    sources: List[Dict[str, Any]]
    evidence_used: List[Dict[str, Any]]
    confidence: Optional[float] = None

