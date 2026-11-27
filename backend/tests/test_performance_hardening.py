from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.correlation.engine import correlate_events
from app.database.session import Base
from app.models.entities import DetectionResult, SecurityEvent
from app.api.endpoints import get_alerts
from app.detection.engine import _should_suppress_borderline_flow_alert
from app.rag.indexer import KnowledgeRetriever
from ml.preprocessing.cicids_pipeline import (
    HostWindowAggregator,
    add_protocol_invariant_features,
    _get_feature_cols,
    enrich_flow_with_host_context,
)
from ml.evaluation.open_set_pipeline import adaptive_family_thresholds
from ml.evaluation.evaluate_rag_quality import comprehensive_rag_cases


def test_host_window_features_and_offline_fallback():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    flows = pd.DataFrame([
        {"Source IP": "10.0.0.1", "Destination Port": 80, "Timestamp": start,
         "Destination IP": "10.0.1.1",
         "SYN Flag Count": 1, "ACK Flag Count": 0, "Total Length of Fwd Packets": 10,
         "Total Length of Bwd Packets": 5},
        {"Source IP": "10.0.0.1", "Destination Port": 443, "Timestamp": start + timedelta(seconds=5),
         "Destination IP": "10.0.1.2",
         "SYN Flag Count": 1, "ACK Flag Count": 1, "Total Length of Fwd Packets": 20,
         "Total Length of Bwd Packets": 10},
    ])
    enriched = enrich_flow_with_host_context(flows, HostWindowAggregator())
    assert enriched.iloc[-1]["distinct_dst_ports_1m"] == 2
    assert enriched.iloc[-1]["syn_to_ack_ratio"] == 2
    assert enriched.iloc[-1]["mean_bytes_per_flow"] == 22.5
    assert enriched.iloc[-1]["win_unique_dst_ports_60s"] == 2
    assert enriched.iloc[-1]["win_unique_dst_ips_60s"] == 2
    assert enriched.iloc[-1]["win_syn_only_ratio_60s"] == 0.5
    assert enriched.iloc[-1]["win_flow_rate_60s"] == 2 / 60
    zeros = enrich_flow_with_host_context(pd.DataFrame([{"flow": 1}]), HostWindowAggregator())
    assert zeros.iloc[0]["flow_inter_arrival_variance"] == 0


def test_session_sanitization_removes_topology_fields():
    frame = pd.DataFrame({"Source IP": [1.0], "Source Port": [2], "Destination IP": [3.0],
                          "Timestamp": [1.0], "Flow ID": [4.0], "Destination Port": [443],
                          "Flow IAT Std": [2.0], "Flow IAT Mean": [4.0],
                          "Total Length of Fwd Packets": [20], "Total Length of Bwd Packets": [10],
                          "Flow Duration": [10], "Label": ["BENIGN"]})
    add_protocol_invariant_features(frame, sanitize_session_features=True)
    features = _get_feature_cols(frame, sanitize_session_features=True)
    assert not {"Source IP", "Source Port", "Destination IP", "Timestamp", "Flow ID", "Destination Port"} & set(features)
    assert {"iat_cv", "fwd_bwd_byte_ratio", "is_well_known_port", "is_registered_port", "is_ephemeral_port"} <= set(features)
    assert frame.loc[0, "iat_cv"] == pytest.approx(0.5)
    assert frame.loc[0, "is_well_known_port"] == 1


def test_adaptive_threshold_uses_each_predicted_family():
    result = adaptive_family_thresholds(np.array([1., 2., 10., 20.]), np.array([0, 0, 1, 1]))
    assert result["by_predicted_class"]["0"] == 1.95
    assert result["by_predicted_class"]["1"] == 19.5


def test_borderline_network_only_alert_is_suppressed():
    event = {"event_id": "flow-1", "timestamp": datetime.now(timezone.utc),
             "event_category": "network", "event_type": "flow", "status": "success",
             "detection_result": {"verdict": "KNOWN_THREAT", "layer": "network",
                                  "probability": .6, "details": {}}}
    result = correlate_events([event])
    assert result["alerts"][0]["alert_status"] == "NOISE_SUPPRESSED"
    assert result["incidents"] == []
    assert result["alert_suppression_ratio"] == 1.0


def test_rag_suite_has_50_labeled_cases_in_required_categories():
    cases = comprehensive_rag_cases()
    counts = {category: sum(row["category"] == category for row in cases)
              for category in {row["category"] for row in cases}}
    assert len(cases) == 50
    assert counts == {"direct_attack_mapping": 20, "adversarial_obfuscated": 15,
                      "multi_hop_investigation": 15}


def test_hybrid_bm25_dense_rrf_puts_exact_technique_first():
    class Embedder:
        def encode(self, _texts, **_kwargs):
            return np.array([[1.0, 0.0]], dtype=np.float32)
    retriever = KnowledgeRetriever.__new__(KnowledgeRetriever)
    retriever.embedder = Embedder()
    retriever.backend = "numpy"
    retriever.index = None
    retriever.vectors = np.array([[1.0, 0.0], [0.3, 0.95]], dtype=np.float32)
    retriever.chunks = [
        {"chunk_id": "generic", "title": "Windows access", "text": "Account access monitoring and remote sessions."},
        {"chunk_id": "t1110", "title": "T1110 Brute Force", "text": "T1110 detects password guessing and failed logins."},
    ]
    retriever.min_relevance_score = 0.25
    results = retriever.search("T1110", top_k=2)
    assert results[0]["chunk_id"] == "t1110"
    assert results[0]["lexical_rank"] == 1


def test_suppressed_flow_keeps_raw_event_but_leaves_alert_queue():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        event = SecurityEvent(event_id="noise-flow", timestamp=datetime.now(timezone.utc),
                              event_category="network", event_type="flow", source_ip="198.51.100.8")
        detection = DetectionResult(detection_id="noise-detection", event_id="noise-flow",
                                    verdict="KNOWN_THREAT", probability=.6, attack_probability=.6,
                                    layer="network", details={})
        session.add_all([event, detection]); session.commit()
        assert _should_suppress_borderline_flow_alert(
            event, {"verdict": "KNOWN_THREAT", "probability": .6}, {"inputs": {}}, session
        )
        detail = dict(detection.details or {})
        detail["alert_status"] = "NOISE_SUPPRESSED"
        detection.details = detail
        session.commit()
        assert session.query(SecurityEvent).filter_by(event_id="noise-flow").count() == 1
        assert get_alerts(verdict=None, limit=50, db=session) == []
    finally:
        session.close()
        engine.dispose()
