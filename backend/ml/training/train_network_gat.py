"""Train a lightweight edge-aware GAT on UNSW-NB15 or a replay sample."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn.functional as F

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
from ml.sequence_graph import (GRAPH_EDGE_DIM, GRAPH_NODE_DIM, GraphAttentionNetwork,
                              build_host_graph, generate_synthetic_graph, load_unsw_frame)

ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "network_gat.bundle.pkl"


def _load_replay_graph(path: Path):
    import pandas as pd
    frame = pd.read_csv(path, compression="gzip", low_memory=False)
    columns = {str(name).strip().lower(): name for name in frame.columns}
    def pick(*names):
        return next((columns[name.lower()] for name in names if name.lower() in columns), None)
    source, destination = pick("Source IP", "srcip"), pick("Destination IP", "dstip")
    if not source or not destination:
        return None
    def series(*names, default=None):
        col = pick(*names)
        return frame[col] if col else default
    return pd.DataFrame({
        "srcip": frame[source].astype(str), "dstip": frame[destination].astype(str),
        "proto": series("Protocol", "proto", default=""), "service": series("service", default=""),
        "sbytes": series("Total Length of Fwd Packets", "sbytes", default=0),
        "dbytes": series("Total Length of Bwd Packets", "dbytes", default=0),
        "dur": series("Flow Duration", "dur", default=0),
        "attack_cat": series("family", "Label", "attack_cat", default=""),
    })


def train_network_gat(dataset_dir: Path | None = None, output_path: Path | None = None,
                      epochs: int = 20, seed: int = 42) -> Path:
    torch.manual_seed(seed)
    np.random.seed(seed)
    root = Path(dataset_dir) if dataset_dir else BACKEND_DIR / "datasets"
    unsw_dir = root / "unsw_nb15" if (root / "unsw_nb15").exists() else root
    unsw_present = unsw_dir.is_dir() and any(unsw_dir.glob("UNSW-NB15_[1-4].csv"))
    frame = load_unsw_frame(unsw_dir) if unsw_present else None
    source = "unsw_nb15"
    if unsw_present and (frame is None or frame.empty):
        raise ValueError(f"UNSW-NB15 CSV files were found but did not contain usable rows: {unsw_dir}")
    if not unsw_present:
        replay = root / "replay" / "replay_sample.csv.gz"
        if replay.is_file():
            frame = _load_replay_graph(replay)
            if frame is None or frame.empty:
                raise ValueError(f"Replay sample was found but has no usable src/dst rows: {replay}")
            source = "replay_sample"
    if frame is not None and not frame.empty:
        graph = build_host_graph(frame, max_edges=12_000, seed=seed)
    else:
        # CI fallback is synthetic only when local graph dataset files are absent.
        graph = generate_synthetic_graph(512, seed)
        source = "synthetic_fallback"
    x = torch.as_tensor(graph["node_features"], dtype=torch.float32)
    edges = torch.as_tensor(graph["edge_index"], dtype=torch.long)
    edge_attr = torch.as_tensor(graph["edge_features"], dtype=torch.float32)
    y = torch.as_tensor(graph["labels"], dtype=torch.float32)
    model = GraphAttentionNetwork(GRAPH_NODE_DIM, GRAPH_EDGE_DIM)
    optimizer = torch.optim.Adam(model.parameters(), lr=.003, weight_decay=1e-4)
    positives = float(y.sum())
    negatives = max(1.0, float(len(y)) - positives)
    pos_weight = torch.tensor([min(negatives / max(1.0, positives), 25.0)])
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits, _ = model(x, edges, edge_attr)
        loss = F.binary_cross_entropy_with_logits(logits, y, pos_weight=pos_weight)
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        logits, attention = model(x, edges, edge_attr)
        probabilities = torch.sigmoid(logits).cpu().numpy()
        attention = attention.cpu().numpy()
    top_indexes = np.argsort(attention)[-100:][::-1]
    top_edges = [{"srcip": graph["hosts"][int(graph["edge_index"][0, i])],
                  "dstip": graph["hosts"][int(graph["edge_index"][1, i])],
                  "attention": float(attention[i]), "attack_probability": float(probabilities[i])}
                 for i in top_indexes]
    destination = Path(output_path) if output_path else ARTIFACT_PATH
    bundle = {
        "model": model, "host_index": {host: i for i, host in enumerate(graph["hosts"])},
        "node_features_by_host": {host: graph["node_features"][i] for i, host in enumerate(graph["hosts"])},
        "incoming_by_host": graph["incoming_by_host"], "top_training_edges": top_edges,
        "node_feature_dim": GRAPH_NODE_DIM, "edge_feature_dim": GRAPH_EDGE_DIM,
        "model_version": "network-gat-v1", "training_source": source,
        "training_rows": int(len(graph["labels"])), "positive_rows": int(positives),
        "seed": seed, "training_date": datetime.now(timezone.utc).isoformat(),
        "target_note": "UNSW attack_cat non-benign indicator; multi-host anomaly proxy, not ground-truth lateral movement labels",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, destination, compress=3)
    return destination


if __name__ == "__main__":
    print(f"Network GAT artifact: {train_network_gat()}")
