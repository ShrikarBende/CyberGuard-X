"""Temporal user-sequence and host-communication graph features/models."""
from __future__ import annotations

import csv
import json
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import torch
from torch import nn
import torch.nn.functional as F

USER_FEATURE_NAMES = [
    "logon_success_count", "logon_failure_count", "process_creation_count",
    "host_transition_flag", "privilege_elevation_flag", "command_execution_count",
    "after_hours_flag", "unique_hosts_count", "session_gap_minutes",
]
UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smean", "dmean", "trans_depth", "response_body_len",
    "sjit", "djit", "Stime", "Ltime", "sinpkt", "dinpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]
GRAPH_NODE_DIM = 6
GRAPH_EDGE_DIM = 5


def _parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _records_from_text(text: str) -> list[Mapping[str, Any]]:
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [item for item in obj if isinstance(item, Mapping)]
        if isinstance(obj, Mapping):
            return [obj]
    except json.JSONDecodeError:
        pass
    rows = []
    for line in text.splitlines():
        try:
            item = json.loads(line.rstrip(","))
        except json.JSONDecodeError:
            continue
        if isinstance(item, Mapping):
            rows.append(item)
    return rows


def _read_json_capture(path: Path) -> list[Mapping[str, Any]]:
    if path.suffix.lower() == ".zip":
        records = []
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if Path(member).suffix.lower() in {".json", ".jsonl"}:
                    with archive.open(member) as stream:
                        records.extend(_records_from_text(stream.read().decode("utf-8-sig", errors="replace")))
        return records
    return _records_from_text(path.read_text(encoding="utf-8-sig", errors="replace"))


def _user_row(record: Mapping[str, Any], prior_host: str = "", previous_time: datetime | None = None,
              hosts_seen: set[str] | None = None) -> tuple[str, datetime, np.ndarray, str] | None:
    event = record.get("Event", record)
    if not isinstance(event, Mapping):
        return None
    event_data = event.get("EventData", {})
    if isinstance(event_data, Mapping) and isinstance(event_data.get("Data"), list):
        flattened = {}
        for item in event_data["Data"]:
            if isinstance(item, Mapping) and item.get("Name"):
                flattened[str(item["Name"])] = item.get("#text", item.get("Value", item.get("value", "")))
        data = {**event, **flattened}
    else:
        data = {**event, **(event_data if isinstance(event_data, Mapping) else {})}
    user = str(data.get("SubjectUserName") or data.get("User") or data.get("user") or
               data.get("TargetUserName") or data.get("AccountName") or "").strip()
    host = str(data.get("Hostname") or data.get("Computer") or data.get("host") or data.get("pc") or "unknown")
    stamp = _parse_time(data.get("@timestamp") or data.get("TimeCreated") or data.get("timestamp") or
                        (data.get("System", {}).get("TimeCreated", {}).get("SystemTime")
                         if isinstance(data.get("System"), Mapping) else None))
    if not user or not stamp or user.endswith("$"):
        return None
    event_id = data.get("EventID") or (data.get("System", {}).get("EventID") if isinstance(data.get("System"), Mapping) else None)
    if isinstance(event_id, Mapping):
        event_id = event_id.get("#text")
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        event_id = -1
    message = str(data.get("Message", "")).lower()
    status = str(data.get("Status", data.get("status", ""))).lower()
    command = str(data.get("CommandLine") or data.get("ProcessCommandLine") or data.get("Image") or
                  data.get("ProcessName") or "").lower()
    success = int(event_id == 4624 or ("logon" in str(data.get("event_type", "")).lower() and status in {"success", "0x0"}))
    failure = int(event_id == 4625 or "failed" in message or status in {"failure", "0xc000006d"})
    process = int(event_id in {1, 4688} or bool(data.get("NewProcessName")))
    command_exec = int(process and any(token in command for token in ("powershell", "cmd.exe", "wscript", "cscript", "rundll32", "bash")))
    elevated = int(event_id == 4672 or str(data.get("IntegrityLevel", "")).lower() in {"high", "system"} or
                   "elevat" in str(data.get("PrivilegeList", "")).lower())
    seen = hosts_seen if hosts_seen is not None else set()
    transition = int(bool(prior_host and host != prior_host))
    seen.add(host)
    gap = max(0.0, (stamp - previous_time).total_seconds() / 60) if previous_time else 0.0
    row = np.asarray([success, failure, process, transition, elevated, command_exec,
                      int(stamp.hour < 6 or stamp.hour >= 22), len(seen), min(gap, 1440)], dtype=np.float32)
    return user, stamp, row, host


def load_user_sequences(sysmon_dir: str | Path, cert_dir: str | Path | None = None,
                        sequence_length: int = 24) -> tuple[np.ndarray, np.ndarray]:
    """Parse Sysmon/Windows JSON and optional CERT logon.csv into padded sequences.

    Returns ``(sequences, weak_risk_labels)``. Since public OTRF captures do not
    include account-takeover ground truth, labels are explicit weak indicators
    based on failed logons, host transitions, elevation, and command bursts.
    """
    per_user: dict[str, list[tuple[datetime, np.ndarray, str]]] = defaultdict(list)
    paths = []
    root = Path(sysmon_dir)
    if root.is_dir():
        paths = sorted([*root.rglob("*.json"), *root.rglob("*.jsonl")])
        if not paths:
            paths = sorted(root.rglob("*.zip"))
    for path in paths:
        for record in _read_json_capture(path):
            parsed = _user_row(record)
            if parsed:
                user, stamp, row, host = parsed
                per_user[user].append((stamp, row, host))
    cert = Path(cert_dir) if cert_dir else None
    if cert and cert.is_dir():
        for path in cert.rglob("logon.csv"):
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
                for item in csv.DictReader(stream):
                    user = str(item.get("user") or item.get("id") or "").strip()
                    stamp = _parse_time(item.get("date"))
                    if not user or not stamp:
                        continue
                    activity = str(item.get("activity", "")).lower()
                    host = str(item.get("pc", "unknown"))
                    row = np.zeros(len(USER_FEATURE_NAMES), dtype=np.float32)
                    row[0] = int("logon" in activity or "login" in activity)
                    row[1] = int("fail" in activity)
                    per_user[user].append((stamp, row, host))

    sequences, labels = [], []
    for user, events in per_user.items():
        events.sort(key=lambda item: item[0])
        prior_host, previous_time, seen = "", None, set()
        enriched = []
        for stamp, row, host in events:
            gap = max(0.0, (stamp - previous_time).total_seconds() / 60) if previous_time else 0.0
            row[3] = int(bool(prior_host and host != prior_host))
            row[7] = len(seen | {host})
            row[8] = min(gap, 1440)
            seen.add(host)
            enriched.append((stamp, row, host))
            prior_host, previous_time = host, stamp
        for offset in range(0, len(enriched), sequence_length):
            chunk = enriched[offset:offset + sequence_length]
            if not chunk:
                continue
            values = np.zeros((sequence_length, len(USER_FEATURE_NAMES)), dtype=np.float32)
            values[-len(chunk):] = np.stack([item[1] for item in chunk])
            # Weak labels support training without claiming verified takeover labels.
            risk = values[:, [1, 3, 4, 5, 6]].sum()
            sequences.append(values)
            labels.append(float(risk >= 3))
    return (np.asarray(sequences, dtype=np.float32).reshape((-1, sequence_length, len(USER_FEATURE_NAMES))),
            np.asarray(labels, dtype=np.float32))


def generate_synthetic_user_sequences(n: int = 512, seed: int = 42, sequence_length: int = 24):
    rng = np.random.default_rng(seed)
    x = rng.poisson(.1, (n, sequence_length, len(USER_FEATURE_NAMES))).astype(np.float32)
    x[:, :, 0] = rng.poisson(.3, (n, sequence_length))
    x[:, :, 2] = rng.poisson(1.2, (n, sequence_length))
    x[:, :, 7] = 1
    y = np.zeros(n, dtype=np.float32)
    positive = np.arange(n) >= n // 2
    x[positive, :, 1] += rng.binomial(1, .45, (positive.sum(), sequence_length))
    x[positive, :, 3] += rng.binomial(1, .55, (positive.sum(), sequence_length))
    x[positive, :, 4] += rng.binomial(1, .5, (positive.sum(), sequence_length))
    x[positive, :, 5] += rng.binomial(1, .6, (positive.sum(), sequence_length))
    x[positive, :, 6] += rng.binomial(1, .3, (positive.sum(), sequence_length))
    y[positive] = 1
    return x, y


class GatedResidualNetwork(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.gate = nn.Linear(hidden_dim, hidden_dim)
        self.skip = nn.Linear(input_dim, hidden_dim) if input_dim != hidden_dim else nn.Identity()
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(self, x):
        hidden = self.fc2(F.elu(self.fc1(x)))
        return self.norm(self.skip(x) + torch.sigmoid(self.gate(hidden)) * hidden)


class TemporalFusionTransformer(nn.Module):
    """Compact TFT-style variable selector, LSTM, gated network, and attention."""
    def __init__(self, input_dim: int, hidden_dim: int = 32, heads: int = 4):
        super().__init__()
        self.variable_weights = nn.Linear(input_dim, input_dim)
        self.variable_embeddings = nn.ModuleList([nn.Linear(1, hidden_dim) for _ in range(input_dim)])
        self.variable_grn = GatedResidualNetwork(hidden_dim, hidden_dim)
        self.lstm = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)
        self.temporal_grn = GatedResidualNetwork(hidden_dim, hidden_dim)
        self.attention = nn.MultiheadAttention(hidden_dim, heads, batch_first=True)
        self.output = nn.Sequential(GatedResidualNetwork(hidden_dim, hidden_dim), nn.Linear(hidden_dim, 1))

    def forward(self, x, valid_mask=None):
        if valid_mask is None:
            valid_mask = torch.any(x != 0, dim=-1)
            # Avoid an all-masked attention row for an empty live-history probe.
            empty_rows = ~valid_mask.any(dim=1)
            if empty_rows.any():
                valid_mask = valid_mask.clone()
                valid_mask[empty_rows, -1] = True
        weights = torch.softmax(self.variable_weights(x), dim=-1)
        values = torch.stack([layer(x[..., i:i + 1]) for i, layer in enumerate(self.variable_embeddings)], dim=-2)
        selected = (values * weights.unsqueeze(-1)).sum(dim=-2)
        encoded, _ = self.lstm(self.variable_grn(selected))
        encoded = self.temporal_grn(encoded)
        attended, attention = self.attention(
            encoded, encoded, encoded, key_padding_mask=~valid_mask.bool(),
            need_weights=True, average_attn_weights=False,
        )
        logits = self.output(encoded + attended).squeeze(-1)
        return logits[:, -1], attention.mean(dim=1), weights


def predict_user_sequence(sequence: np.ndarray, bundle: Mapping[str, Any]) -> dict[str, Any]:
    values = np.asarray(sequence, dtype=np.float32)
    if values.ndim == 2:
        values = values[None, ...]
    if values.ndim != 3 or values.shape[2] != len(bundle["feature_names"]):
        raise ValueError("user sequence must have shape (steps, features)")
    expected = int(bundle["sequence_length"])
    values = values[:, -expected:, :]
    if values.shape[1] < expected:
        pad = np.zeros((len(values), expected - values.shape[1], values.shape[2]), dtype=np.float32)
        values = np.concatenate((pad, values), axis=1)
    valid_mask = np.any(values != 0, axis=-1)
    empty_rows = ~valid_mask.any(axis=1)
    valid_mask[empty_rows, -1] = True
    values = np.clip((values - bundle["feature_min"]) / bundle["feature_range"], 0, 1)
    x = torch.as_tensor(values, dtype=torch.float32)
    bundle["model"].eval()
    with torch.no_grad():
        logits, attention, variable_weights = bundle["model"](x, torch.as_tensor(valid_mask, dtype=torch.bool))
        score = torch.sigmoid(logits)[0].item()
        per_step = attention[0, -1, :].cpu().numpy()
        selection = variable_weights[0, -1, :].cpu().numpy()
    return {"s_user": float(np.clip(score, 0, 1)),
            "temporal_attention": [float(v) for v in per_step],
            "variable_selection_weights": {name: float(v) for name, v in zip(bundle["feature_names"], selection)}}


def sequence_for_event(event: Any, length: int, history: list[Any] | None = None) -> np.ndarray:
    """Encode a live event with recent per-user history or supplied payload history."""
    payload = getattr(event, "raw_payload", None) or {}
    payload_history = payload.get("user_sequence") if isinstance(payload, Mapping) else None
    if payload_history is not None:
        values = np.asarray(payload_history, dtype=np.float32)
        return values[-length:]
    rows = []
    for item in [*(history or []), event]:
        typ = str(getattr(item, "event_type", "")).lower()
        category = str(getattr(item, "event_category", "")).lower()
        timestamp = getattr(item, "timestamp", datetime.now(timezone.utc))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        row = np.zeros(len(USER_FEATURE_NAMES), dtype=np.float32)
        row[0] = float("logon" in typ and getattr(item, "status", "success") == "success")
        row[1] = float(getattr(item, "status", "").lower() in {"failed", "failure", "blocked"})
        row[2] = float(category == "endpoint" and ("process" in typ or "create" in typ))
        row[4] = float(str(getattr(item, "privilege_level", "")).lower() in {"admin", "system", "high"})
        row[5] = float(bool(getattr(item, "command_line", None)))
        row[6] = float(timestamp.hour < 6 or timestamp.hour >= 22)
        rows.append((timestamp, row, str(getattr(item, "device_id", "") or "unknown")))
    rows.sort(key=lambda item: item[0])
    seen = set()
    previous_host, previous_time = "", None
    encoded = []
    for timestamp, row, host in rows:
        row[3] = int(bool(previous_host and previous_host != host))
        seen.add(host)
        row[7] = len(seen)
        row[8] = min(max(0.0, (timestamp - previous_time).total_seconds() / 60), 1440) if previous_time else 0
        encoded.append(row)
        previous_host, previous_time = host, timestamp
    return np.stack(encoded[-length:]) if encoded else np.zeros((0, len(USER_FEATURE_NAMES)), dtype=np.float32)


def _numeric(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
        return parsed if np.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def graph_edge_features(row: Mapping[str, Any]) -> np.ndarray:
    proto_map = {"tcp": 1.0, "udp": 0.5, "icmp": 0.25}
    proto = str(row.get("proto", "")).lower()
    service_map = {"http": .2, "ftp": .4, "smtp": .6, "dns": .8, "ssh": 1.0}
    service = str(row.get("service", "")).lower()
    return np.asarray([np.log1p(max(0, _numeric(row.get("sbytes")))),
                       np.log1p(max(0, _numeric(row.get("dbytes")))),
                       np.log1p(max(0, _numeric(row.get("dur")))),
                       proto_map.get(proto, .1), service_map.get(service, 0.0)], dtype=np.float32)


def build_host_graph(frame, max_edges: int = 12_000, seed: int = 42) -> dict[str, Any]:
    """Build directed srcip→dstip edges and train-only host aggregates."""
    if len(frame) > max_edges:
        frame = frame.sample(n=max_edges, random_state=seed).reset_index(drop=True)
    required = {"srcip", "dstip", "proto", "service", "sbytes", "dbytes", "dur", "attack_cat"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"network rows are missing columns: {sorted(missing)}")
    hosts = sorted(set(frame["srcip"].astype(str)) | set(frame["dstip"].astype(str)))
    indexes = {host: i for i, host in enumerate(hosts)}
    node = np.zeros((len(hosts), GRAPH_NODE_DIM), dtype=np.float32)
    edges, edge_features, labels = [], [], []
    outgoing_neighbors = defaultdict(set)
    incoming_neighbors = defaultdict(set)
    incoming = defaultdict(list)
    for row in frame.to_dict("records"):
        src, dst = str(row["srcip"]), str(row["dstip"])
        si, di = indexes[src], indexes[dst]
        ef = graph_edge_features(row)
        edges.append((si, di)); edge_features.append(ef)
        attack = str(row.get("attack_cat", "")).strip().lower()
        labels.append(float(attack not in {"", "nan", "normal", "benign", "-"}))
        node[si, 0] += 1; node[di, 1] += 1
        node[si, 2] += max(0.0, _numeric(row.get("sbytes")))
        node[di, 3] += max(0.0, _numeric(row.get("dbytes")))
        outgoing_neighbors[src].add(dst)
        incoming_neighbors[dst].add(src)
        incoming[dst].append((src, ef))
    node[:, 2:4] = np.log1p(node[:, 2:4])
    for host in hosts:
        node[indexes[host], 4] = len(outgoing_neighbors[host])
        node[indexes[host], 5] = len(incoming_neighbors[host])
    node[:, 0:2] = np.log1p(node[:, 0:2])
    incoming_small = {host: [(src, attr.tolist()) for src, attr in vals[:8]] for host, vals in incoming.items()}
    return {"hosts": hosts, "node_features": node, "edge_index": np.asarray(edges, dtype=np.int64).T,
            "edge_features": np.asarray(edge_features, dtype=np.float32), "labels": np.asarray(labels, dtype=np.float32),
            "incoming_by_host": incoming_small}


def load_unsw_frame(dataset_dir: str | Path, max_rows_per_file: int = 12_000):
    import pandas as pd
    paths = sorted(Path(dataset_dir).glob("UNSW-NB15_[1-4].csv"))
    if not paths:
        return None
    frames = []
    for path in paths:
        frame = pd.read_csv(path, header=None, names=UNSW_COLUMNS, nrows=max_rows_per_file,
                            low_memory=False, encoding="latin-1")
        frames.append(frame)
    frame = pd.concat(frames, ignore_index=True)
    frame["attack_cat"] = frame["attack_cat"].fillna("").astype(str)
    return frame


def generate_synthetic_graph(n_edges: int = 512, seed: int = 42) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    n_hosts = max(16, n_edges // 8)
    hosts = [f"synthetic-{i}" for i in range(n_hosts)]
    edges = rng.integers(0, n_hosts, size=(2, n_edges), dtype=np.int64)
    edges[1] = (edges[0] + rng.integers(1, n_hosts, size=n_edges)) % n_hosts
    labels = (rng.random(n_edges) < .2).astype(np.float32)
    edge_attr = rng.random((n_edges, GRAPH_EDGE_DIM), dtype=np.float32)
    edge_attr[labels == 1, :3] += 3
    node = rng.random((n_hosts, GRAPH_NODE_DIM), dtype=np.float32)
    incoming = defaultdict(list)
    for (src, dst), attr in zip(edges.T, edge_attr):
        incoming[hosts[int(dst)]].append((hosts[int(src)], attr.tolist()))
    return {"hosts": hosts, "node_features": node, "edge_index": edges, "edge_features": edge_attr,
            "labels": labels, "incoming_by_host": dict(incoming)}


class GraphAttentionNetwork(nn.Module):
    """Single-head edge-aware GAT with explicit destination-normalized αᵢⱼ."""
    def __init__(self, node_dim: int = GRAPH_NODE_DIM, edge_dim: int = GRAPH_EDGE_DIM, hidden_dim: int = 24):
        super().__init__()
        self.node_projection = nn.Linear(node_dim, hidden_dim)
        self.edge_projection = nn.Linear(edge_dim, hidden_dim)
        self.attn_src = nn.Parameter(torch.empty(hidden_dim))
        self.attn_dst = nn.Parameter(torch.empty(hidden_dim))
        self.attn_edge = nn.Parameter(torch.empty(hidden_dim))
        nn.init.xavier_uniform_(self.attn_src.unsqueeze(0)); nn.init.xavier_uniform_(self.attn_dst.unsqueeze(0)); nn.init.xavier_uniform_(self.attn_edge.unsqueeze(0))
        self.update = nn.Linear(hidden_dim * 2, hidden_dim)
        self.classifier = nn.Sequential(nn.Linear(hidden_dim * 3 + edge_dim + 1, hidden_dim), nn.ELU(), nn.Linear(hidden_dim, 1))

    def forward(self, node_features, edge_index, edge_features):
        src, dst = edge_index[0], edge_index[1]
        h = F.elu(self.node_projection(node_features))
        e = F.elu(self.edge_projection(edge_features))
        logits_attn = F.leaky_relu((h[src] * self.attn_src).sum(-1) +
                                   (h[dst] * self.attn_dst).sum(-1) +
                                   (e * self.attn_edge).sum(-1), .2)
        max_by_dst = torch.full((len(h),), -torch.inf, dtype=h.dtype, device=h.device)
        max_by_dst.scatter_reduce_(0, dst, logits_attn, reduce="amax", include_self=True)
        exp = torch.exp(logits_attn - max_by_dst[dst])
        denom = torch.zeros(len(h), dtype=h.dtype, device=h.device).index_add_(0, dst, exp)
        alpha = exp / (denom[dst] + 1e-9)
        aggregate = torch.zeros_like(h).index_add_(0, dst, alpha[:, None] * h[src])
        updated = F.elu(self.update(torch.cat((h, aggregate), dim=-1)))
        edge_logits = self.classifier(torch.cat((updated[src], updated[dst], e, edge_features, alpha[:, None]), dim=-1)).squeeze(-1)
        return edge_logits, alpha


def predict_graph_edge(source: str, destination: str, features: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Score one live flow using a small stored incoming neighborhood for attention."""
    known_hosts = bundle["host_index"]
    node_map = bundle["node_features_by_host"]
    candidate_edges = list(bundle["incoming_by_host"].get(destination, []))
    target_attr = graph_edge_features(features)
    candidate_edges = [(src, destination, np.asarray(attr, dtype=np.float32)) for src, attr in candidate_edges
                       if src in node_map]
    candidate_edges.append((source, destination, target_attr))
    host_ids = [source, destination] + [host for edge in candidate_edges for host in edge[:2]]
    ids = list(dict.fromkeys(host_ids)); mapping = {host: i for i, host in enumerate(ids)}
    nodes = np.stack([node_map.get(host, np.zeros(GRAPH_NODE_DIM, dtype=np.float32)) for host in ids])
    edge_index = np.asarray([[mapping[src] for src, _, _ in candidate_edges],
                             [mapping[dst] for _, dst, _ in candidate_edges]], dtype=np.int64)
    edge_attrs = np.stack([attr for _, _, attr in candidate_edges]).astype(np.float32)
    model = bundle["model"]; model.eval()
    with torch.no_grad():
        logits, attention = model(torch.as_tensor(nodes), torch.as_tensor(edge_index), torch.as_tensor(edge_attrs))
        probability = torch.sigmoid(logits).cpu().numpy()
        alphas = attention.cpu().numpy()
    idx = len(candidate_edges) - 1
    top = sorted(({"srcip": src, "dstip": dst, "attention": float(alpha), "attack_probability": float(prob)}
                  for (src, dst, _), alpha, prob in zip(candidate_edges, alphas, probability)),
                 key=lambda item: item["attention"], reverse=True)[:5]
    return {"s_network_graph": float(np.clip(probability[idx], 0, 1)),
            "edge_attention": float(alphas[idx]), "top_suspicious_edges": top}
