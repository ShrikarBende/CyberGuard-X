"""User TFT and network GAT parsing, inference, attention, and fallback tests."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from ml.sequence_graph import (GRAPH_EDGE_DIM, GRAPH_NODE_DIM, USER_FEATURE_NAMES,
                              GraphAttentionNetwork, TemporalFusionTransformer,
                              build_host_graph, load_user_sequences, predict_graph_edge,
                              predict_user_sequence)
from ml.training.train_network_gat import train_network_gat
from ml.training.train_user_tft import train_user_tft
from app.database.session import Base
from app.detection import engine as detection_engine
from app.models import entities  # noqa: F401
from app.schemas.schemas import SecurityEventCreate


def test_sysmon_user_session_parser_extracts_chronology_and_features(tmp_path):
    root = tmp_path / "sysmon"
    root.mkdir()
    capture = root / "events.jsonl"
    events = [
        {"@timestamp": "2024-01-01T01:00:00Z", "EventID": 4624,
         "SubjectUserName": "alice", "Hostname": "host-a"},
        {"@timestamp": "2024-01-01T01:03:00Z", "EventID": 4625,
         "SubjectUserName": "alice", "Hostname": "host-b", "Message": "Logon failed"},
        {"@timestamp": "2024-01-01T01:04:00Z", "EventID": 4672,
         "SubjectUserName": "alice", "Hostname": "host-b"},
        {"@timestamp": "2024-01-01T01:05:00Z", "EventID": 1,
         "SubjectUserName": "alice", "Hostname": "host-b", "Image": "powershell.exe"},
    ]
    capture.write_text("\n".join(json.dumps(row) for row in events), encoding="utf-8")
    sequences, labels = load_user_sequences(root, sequence_length=8)
    assert sequences.shape == (1, 8, len(USER_FEATURE_NAMES))
    tail = sequences[0, -4:]
    assert tail[0, 0] == 1
    assert tail[1, 1] == 1
    assert tail[1, 3] == 1
    assert tail[2, 4] == 1
    assert tail[3, 2] == 1 and tail[3, 5] == 1
    assert labels.tolist() == [1.0]


def test_unsw_schema_builds_host_to_host_graph():
    rows = pd.DataFrame([
        {"srcip": "10.0.0.1", "dstip": "10.0.0.2", "proto": "tcp", "service": "ssh",
         "sbytes": 100, "dbytes": 200, "dur": .2, "attack_cat": "Normal"},
        {"srcip": "10.0.0.3", "dstip": "10.0.0.2", "proto": "tcp", "service": "ftp",
         "sbytes": 900, "dbytes": 30, "dur": 3.0, "attack_cat": "Exploits"},
    ])
    graph = build_host_graph(rows)
    assert graph["edge_index"].shape == (2, 2)
    assert set(graph["hosts"]) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert graph["labels"].tolist() == [0.0, 1.0]
    assert graph["edge_features"].shape == (2, GRAPH_EDGE_DIM)
    assert graph["node_features"].shape == (3, GRAPH_NODE_DIM)


def test_empty_dataset_fallbacks_train_and_expose_attention(tmp_path):
    empty_data = tmp_path / "datasets"
    empty_data.mkdir()
    user_path = train_user_tft(dataset_dir=empty_data, output_path=tmp_path / "user.pkl", epochs=1)
    user_bundle = joblib.load(user_path)
    assert user_bundle["training_source"] == "synthetic_fallback"
    user_result = predict_user_sequence(np.zeros((8, len(USER_FEATURE_NAMES)), dtype=np.float32), user_bundle)
    assert 0 <= user_result["s_user"] <= 1
    assert len(user_result["temporal_attention"]) == user_bundle["sequence_length"]
    assert sum(user_result["temporal_attention"]) == pytest.approx(1.0, abs=1e-5)
    assert sum(weight > 1e-5 for weight in user_result["temporal_attention"]) == 1
    assert sum(user_result["variable_selection_weights"].values()) == pytest.approx(1.0, abs=1e-5)

    graph_path = train_network_gat(dataset_dir=empty_data, output_path=tmp_path / "graph.pkl", epochs=1)
    graph_bundle = joblib.load(graph_path)
    assert graph_bundle["training_source"] == "synthetic_fallback"
    src, dst = next(iter(graph_bundle["host_index"])), None
    dst = next(host for host in graph_bundle["host_index"] if host != src)
    graph_result = predict_graph_edge(src, dst, {"sbytes": 4, "dbytes": 8, "dur": 1,
                                                 "proto": "tcp", "service": "http"}, graph_bundle)
    assert 0 <= graph_result["s_network_graph"] <= 1
    assert 0 <= graph_result["edge_attention"] <= 1
    assert graph_result["top_suspicious_edges"]
    assert all(0 <= item["attention"] <= 1 for item in graph_result["top_suspicious_edges"])



def _finish_inline(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Expected detector coroutine to complete inline")


def test_live_network_event_returns_flow_user_and_graph_scores(monkeypatch):
    from ml import fusion_meta
    monkeypatch.setattr(fusion_meta, "_BUNDLE_CACHE", {})
    db_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=db_engine)
    factory = sessionmaker(bind=db_engine, autocommit=False, autoflush=False)
    user_model = TemporalFusionTransformer(len(USER_FEATURE_NAMES)).eval()
    user_bundle = {"model": user_model, "feature_names": USER_FEATURE_NAMES,
                   "feature_min": np.zeros(len(USER_FEATURE_NAMES), np.float32),
                   "feature_range": np.ones(len(USER_FEATURE_NAMES), np.float32),
                   "sequence_length": 24, "model_version": "test-user"}
    graph_model = GraphAttentionNetwork().eval()
    graph_bundle = {"model": graph_model,
        "host_index": {"10.0.0.1": 0, "10.0.0.2": 1, "10.0.0.3": 2},
        "node_features_by_host": {"10.0.0.1": np.zeros(GRAPH_NODE_DIM, np.float32),
                                  "10.0.0.2": np.ones(GRAPH_NODE_DIM, np.float32),
                                  "10.0.0.3": np.full(GRAPH_NODE_DIM, .5, np.float32)},
        "incoming_by_host": {"10.0.0.2": [("10.0.0.3", [.1, .2, .1, .4, .2])]},
        "model_version": "test-graph"}

    class Scaler:
        def transform(self, values):
            return values

    class FlowModel:
        def predict(self, values, raw_score=False):
            return np.tile(np.array([[0.0, 10.0]]), (len(values), 1))

        def predict_proba(self, values):
            return np.tile(np.array([[.1, .9]]), (len(values), 1))

    flow_bundle = {"model": FlowModel(), "scaler": Scaler(), "feature_names": ["flow_a", "flow_b"],
                   "log1p_columns": [False, False], "class_names": ["BENIGN", "PortScan"],
                   "tau": 1.0, "score_name": "logit_margin", "model_version": "test-flow"}
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: flow_bundle)
    monkeypatch.setattr(detection_engine, "load_user_bundle", lambda: user_bundle)
    monkeypatch.setattr(detection_engine, "load_network_gat_bundle", lambda: graph_bundle)
    with factory() as db:
        result = _finish_inline(detection_engine.process_single_event(SecurityEventCreate(
            event_category="network", event_type="flow", user_id="alice",
            source_ip="10.0.0.1", destination_ip="10.0.0.2",
            raw_payload={"cicids_features": {"flow_a": 1.0, "flow_b": 2.0},
                         "network_graph_features": {"sbytes": 50, "dbytes": 40, "dur": .5,
                                                     "proto": "tcp", "service": "ssh"}},
        ), db))
    assert 0 <= result["s_user"] <= 1
    assert 0 <= result["s_network_flow"] <= 1
    assert 0 <= result["s_network_graph"] <= 1
    assert len(result["temporal_attention"]) == 24
    assert result["top_suspicious_edges"]
    db_engine.dispose()
