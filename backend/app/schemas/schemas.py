"""
Pydantic v2 schemas for Enterprise CyberGuard X.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict


# -------------------------------------------------------------------
# Security Event Schemas
# -------------------------------------------------------------------
class SecurityEventCreate(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
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
    verdict: str  # BENIGN, KNOWN_THREAT, UNKNOWN_NOVEL_THREAT, SUSPICIOUS
    predicted_class: Optional[str] = None
    confidence: float
    anomaly_score: float
    open_set_distance: float
    reconstruction_error: float
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
    confidence: float
    evidence_predicate: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class InvestigationNoteCreate(BaseModel):
    content: str
    author: Optional[str] = "SOC Analyst"


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
    user_risk_component: float
    endpoint_risk_component: float
    network_risk_component: float
    anomaly_factor: float
    correlation_multiplier: float
    top_contributing_features: Optional[List[Dict[str, Any]]] = None
    explanation_summary: Optional[str] = None

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
    total_threats: int
    known_threats: int
    unknown_threats: int
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
    citations: List[Dict[str, Any]]
    retrieved_context_count: int
    confidence: float
    recommended_containment: List[str]


# -------------------------------------------------------------------
# Model Training & Inference Schemas
# -------------------------------------------------------------------
class TrainModelRequest(BaseModel):
    model_name: str = "all"  # isolation_forest, lightgbm, autoencoder, all
    n_samples: int = 1000
    contamination: float = 0.05
    epochs: int = 10


class TrainModelResponse(BaseModel):
    status: str
    message: str
    metrics: Dict[str, Any]
    timestamp: datetime

