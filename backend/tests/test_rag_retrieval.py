from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.database.session import Base
from app.models.entities import DetectionResult, Incident, IncidentEvent, MitreTechnique, SecurityEvent
from app.rag.assistant import query_rag_assistant
from app.rag.indexer import get_retriever, knowledge_hash
from app.rag.assistant import investigate_incident
from ml.training.train_fusion_meta import train_fusion_meta


RETRIEVAL_QUESTIONS = [
    {"question": "What evidence suggests repeated password guessing against an account?", "expected_source_file": "t1110_brute_force.md"},
    {"question": "What should be checked after a burst of failed logins?", "expected_source_file": "t1110_brute_force.md"},
    {"question": "How can stolen credentials be used through a valid account?", "expected_source_file": "t1078_valid_accounts.md"},
    {"question": "What should analysts verify after a login from an unfamiliar device?", "expected_source_file": "t1078_valid_accounts.md"},
    {"question": "What does an encoded PowerShell command line indicate and what records should I inspect?", "expected_source_file": "t1059_001_powershell.md"},
    {"question": "Which endpoint evidence helps investigate suspicious PowerShell execution?", "expected_source_file": "t1059_001_powershell.md"},
    {"question": "How should unusual outbound data transfers through a command channel be investigated?", "expected_source_file": "t1041_exfiltration_c2.md"},
    {"question": "What should be preserved when a host may be sending data to unfamiliar external infrastructure?", "expected_source_file": "t1041_exfiltration_c2.md"},
    {"question": "What traffic pattern can indicate network service discovery?", "expected_source_file": "t1046_network_discovery.md"},
    {"question": "How do I distinguish an authorized port scan from suspicious probing?", "expected_source_file": "t1046_network_discovery.md"},
    {"question": "What should I check for unexpected SMB administrative share access?", "expected_source_file": "t1021_002_smb_admin_shares.md"},
    {"question": "Which evidence helps investigate remote Windows activity over SMB?", "expected_source_file": "t1021_002_smb_admin_shares.md"},
    {"question": "What network signals can indicate a denial of service event?", "expected_source_file": "t1498_network_denial_of_service.md"},
    {"question": "What should be checked before mitigating a sudden traffic spike?", "expected_source_file": "t1498_network_denial_of_service.md"},
    {"question": "Which host-side changes can corroborate an attack against a public application?", "expected_source_file": "t1190_public_facing_app.md"},
    {"question": "What application and proxy evidence should be preserved after suspicious web requests?", "expected_source_file": "t1190_public_facing_app.md"},
    {"question": "What makes ordinary application protocol traffic suspicious as a possible control channel?", "expected_source_file": "t1071_application_layer_protocol.md"},
    {"question": "How can periodic outbound application traffic be investigated?", "expected_source_file": "t1071_application_layer_protocol.md"},
    {"question": "What evidence should be preserved before containing a suspicious host?", "expected_source_file": "ir_evidence_containment.md"},
    {"question": "When a telemetry layer has no trained model, what does NOT_COVERED mean?", "expected_source_file": "project_not_covered.md"},
]


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _stored_incident(db):
    event = SecurityEvent(
        event_id="rag-event-1",
        timestamp=datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc),
        event_category="network",
        event_type="network_flow",
        status="success",
        dataset="test",
    )
    incident = Incident(
        incident_id="rag-incident-1",
        title="Stored test incident",
        description="not included in the retrieval query",
        severity="MEDIUM",
        status="open",
        threat_classification="RULE_CORRELATED_SUSPICIOUS_ACTIVITY",
        overall_risk_score=72.5,
        first_detected_at=datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc),
        last_updated_at=datetime(2026, 11, 15, 10, 1, tzinfo=timezone.utc),
        attack_sequence=[],
        evidence={"indicators": []},
    )
    db.add_all([event, incident])
    db.flush()
    db.add(IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id, stage="classification", order=0))
    db.add(DetectionResult(
        detection_id="rag-detection-1",
        event_id=event.event_id,
        verdict="UNKNOWN_CANDIDATE",
        predicted_class="PortScan",
        confidence=0.18,
        probability=0.63,
        anomaly_score=0.41,
        open_set_distance=5.2,
        model_version="test-model-v1",
        tau=0.22,
        layer="network",
        details={"score": 0.18, "score_name": "logit_margin"},
    ))
    db.add(MitreTechnique(
        incident_id=incident.incident_id,
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        confidence="rule_matched",
        evidence_predicate={"stored": True},
        is_verified=False,
    ))
    db.commit()
    return incident


@pytest.mark.requires_data(reason="Requires the Sentence Transformers embedding model and builds the RAG index.")
def test_retrieval_question_set_hit_at_1_and_3_and_save_results(capsys, tmp_path):
    retriever = get_retriever()
    hit_at_1 = 0
    hit_at_3 = 0
    for item in RETRIEVAL_QUESTIONS:
        results = retriever.search(item["question"], top_k=3)
        expected = item["expected_source_file"]
        source_files = [result["source_file"] for result in results]
        hit_at_1 += bool(source_files and source_files[0] == expected)
        hit_at_3 += expected in source_files
    hit_at_1 /= len(RETRIEVAL_QUESTIONS)
    hit_at_3 /= len(RETRIEVAL_QUESTIONS)
    report = {
        "date": datetime.now().date().isoformat(),
        "model_name": retriever.model_name,
        "knowledge_hash": knowledge_hash(),
        "index_backend": retriever.backend,
        "index_build_time_seconds": round(retriever.build_time_seconds, 4),
        "question_count": len(RETRIEVAL_QUESTIONS),
        "hit_at_1": round(hit_at_1, 4),
        "hit_at_3": round(hit_at_3, 4),
        "questions": RETRIEVAL_QUESTIONS,
    }
    output_dir = tmp_path
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"rag_retrieval_{report['date']}.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with capsys.disabled():
        print(f"RAG hit@1={hit_at_1:.4f} hit@3={hit_at_3:.4f}")
        print(f"RAG index backend={retriever.backend} build_time_seconds={retriever.build_time_seconds:.4f}")
        print(f"RAG retrieval report={output_path}")


@pytest.mark.requires_data(reason="Requires the Sentence Transformers embedding model for retrieval.")
def test_low_score_question_returns_not_enough_documentation(monkeypatch, db_session):
    monkeypatch.setattr(settings, "RAG_MIN_RETRIEVAL_SCORE", 1.01)
    answer = query_rag_assistant("Explain this unrelated quantum gardening phrase.", None, db_session)
    assert answer["answer"] == "I don't have enough documentation to answer this."
    assert answer["sources"] == []


@pytest.mark.requires_data(reason="Requires the Sentence Transformers embedding model for retrieval.")
def test_answer_does_not_claim_confirmed_attack(monkeypatch, db_session):
    monkeypatch.setattr(settings, "LLM_API_URL", "")
    monkeypatch.setattr(settings, "LLM_API_KEY", "")
    answer = query_rag_assistant("What do the demo correlation rules do?", None, db_session)
    text = answer["answer"].lower()
    assert "confirmed attack" not in text or "not a confirmed attack" in text


def test_remediation_execution_request_is_refused(db_session):
    answer = query_rag_assistant("Run remediation and isolate this host now.", None, db_session)
    assert "cannot run remediation" in answer["answer"].lower()
    assert "analyst approval" in answer["answer"].lower()


@pytest.mark.requires_data(reason="Requires the Sentence Transformers embedding model for retrieval.")
def test_incident_without_indicators_says_evidence_is_missing(db_session):
    incident = _stored_incident(db_session)
    answer = query_rag_assistant("Explain this incident and its evidence.", incident, db_session)
    assert "evidence is missing" in answer["answer"].lower()


@pytest.mark.requires_data(reason="Requires the Sentence Transformers embedding model for retrieval.")
def test_evidence_used_matches_values_stored_in_database(db_session):
    incident = _stored_incident(db_session)
    answer = query_rag_assistant("Explain the PortScan evidence and technique.", incident, db_session)
    evidence = {item["field"]: item["value"] for item in answer["evidence_used"]}
    assert evidence["verdict"] == ["UNKNOWN_CANDIDATE"]
    assert evidence["predicted_class"] == ["PortScan"]
    assert evidence["scores"][0]["score"] == 0.18
    assert evidence["scores"][0]["attack_probability"] == 0.41
    assert evidence["scores"][0]["tau"] == 0.22
    assert evidence["event_ids"] == ["rag-event-1"]
    assert evidence["mitre"][0]["technique_id"] == "T1046"
    assert evidence["mitre"][0]["confidence"] == "rule_matched"


def _investigation_incident(db):
    incident = Incident(
        incident_id="investigation-flow", title="Failed login followed by PowerShell",
        severity="HIGH", status="NEEDS_REVIEW", threat_classification="UNKNOWN_NOVEL",
        overall_risk_score=82.0, first_detected_at=datetime.now(timezone.utc),
        last_updated_at=datetime.now(timezone.utc), attack_sequence=[{"stage": "execution"}],
        evidence={"indicators": [{"name": "failed_login_burst", "evidence": {"event_type": "brute_force"}}],
                  "risk_fusion": {"contributions": {"user_contribution": 30.0,
                      "endpoint_contribution": 20.0, "network_contribution": 30.0,
                      "open_set_contribution": 20.0}}},
    )
    event = SecurityEvent(event_id="investigation-event", timestamp=datetime.now(timezone.utc),
                          event_category="auth", event_type="login", status="failure")
    db.add_all([incident, event]); db.flush()
    db.add(IncidentEvent(incident_id=incident.incident_id, event_id=event.event_id, stage="failed_login_burst", order=0))
    db.add(DetectionResult(detection_id="investigation-detection", event_id=event.event_id,
                           verdict="UNKNOWN_NOVEL", predicted_class="PortScan", probability=.8,
                           score=.9, attack_probability=.9, open_set_distance=6.2, layer="network",
                           details={"s_network_flow": .9, "open_set_score": .92,
                                    "top_suspicious_edges": [{"srcip": "a", "dstip": "b", "attention": .8}]}))
    db.commit()
    return incident


class _InvestigationRetriever:
    def __init__(self, score):
        self.score = score

    def search(self, query, top_k=None, extra_documents=None):
        return [{"chunk_id": "T1110:001", "doc_id": "T1110", "source_type": "mitre",
                 "title": "T1110 Brute Force", "text": "MITRE brute-force technique and mitigation.",
                 "supported_indicators": ["failed_login_burst"],
                 "score": self.score, "relevance_score": self.score}]


def test_five_step_investigation_is_read_only_and_maps_only_supported_evidence(monkeypatch, db_session):
    import app.rag.assistant as assistant
    monkeypatch.setattr(assistant, "get_retriever", lambda: _InvestigationRetriever(.85))
    incident = _investigation_incident(db_session)
    before_count = db_session.query(IncidentEvent).count()
    result = investigate_incident(incident, db_session, top_k=3)
    assert [step["step"] for step in result["trace"]] == ["retrieve", "analyze", "map", "summarize", "recommend"]
    assert result["read_only"] is True
    assert result["trace"][0]["results"][0]["source_type"] == "mitre"
    assert result["trace"][0]["results"][0]["doc_id"] == "T1110"
    assert result["trace"][2]["mitre_attack"][0]["technique_id"] == "T1110"
    assert "not confirmed" in result["trace"][3]["executive_summary"]
    assert result["trace"][4]["requires_human_approval"] is True
    assert all(row["requires_human_approval"] for row in result["trace"][4]["actions"])
    assert db_session.query(IncidentEvent).count() == before_count


def test_low_retrieval_score_blocks_mapping_and_recommendations(monkeypatch, db_session):
    import app.rag.assistant as assistant
    monkeypatch.setattr(assistant, "get_retriever", lambda: _InvestigationRetriever(-.1))
    incident = _investigation_incident(db_session)
    result = investigate_incident(incident, db_session)
    retrieve, _analyze, map_step, _summary, recommend = result["trace"]
    assert retrieve["evidence_sufficient"] is False
    assert map_step["mitre_attack"] == []
    assert "insufficient" in map_step["statement"].lower()
    assert recommend["actions"] == []
    assert recommend["requires_human_approval"] is True


def test_fusion_retraining_appends_verified_feedback_without_validation_leakage(tmp_path):
    artifact = tmp_path / "fusion-feedback.joblib"
    samples = [{"target": 1, "fusion_features": {"s_user": .9, "s_endpoint": .8,
                 "s_network_flow": .95, "s_network_graph": .8, "s_open_set_distance": .9,
                 "stage_count": 5}},
               {"target": 0, "fusion_features": {"s_user": .01, "s_endpoint": .02,
                 "s_network_flow": .02, "s_network_graph": .01, "s_open_set_distance": .03,
                 "stage_count": 1}}]
    train_fusion_meta(output_path=artifact, feedback_samples=samples)
    import joblib
    bundle = joblib.load(artifact)
    assert bundle["feedback_samples_used"] == 2
    assert bundle["validation_rows"] < 6000
    assert bundle["threshold_calibration"].startswith("97th percentile")


def test_feedback_builder_records_branch_scores_and_verified_label(db_session):
    from app.api.endpoints import _incident_feedback_sample
    incident = _investigation_incident(db_session)
    sample = _incident_feedback_sample(db_session, incident, "CONFIRMED")
    assert sample["target"] == 1
    assert sample["source_incident_id"] == incident.incident_id
    assert sample["fusion_features"]["s_network_flow"] == pytest.approx(.9)
    assert sample["fusion_features"]["s_open_set_distance"] == pytest.approx(.92)
