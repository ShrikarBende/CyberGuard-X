"""Endpoint telemetry features and benign-only DAE/Isolation Forest scoring."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping
import json
import zipfile

import numpy as np
import torch
from torch import nn

FEATURE_NAMES = [
    "process_creation_rate", "parent_child_anomaly_rate", "privilege_escalation_flags",
    "registry_write_count", "file_write_count", "network_connection_count",
    "cpu_percent", "memory_percent", "failed_process_count",
]


class DenoisingAutoencoder(nn.Module):
    """Small fully connected autoencoder used by training and live inference."""
    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(nn.Linear(input_dim, 16), nn.ReLU(), nn.Linear(16, 8), nn.ReLU())
        self.decoder = nn.Sequential(nn.Linear(8, 16), nn.ReLU(), nn.Linear(16, input_dim), nn.Sigmoid())

    def forward(self, values):
        return self.decoder(self.encoder(values))


def _event_parts(record: Mapping[str, Any]) -> tuple[int | None, Mapping[str, Any]]:
    """Read common OTRF/Mordor and Windows Event JSON representations."""
    event = record.get("Event", record)
    if not isinstance(event, Mapping):
        return None, {}
    system = event.get("System", {})
    event_id = (system.get("EventID") if isinstance(system, Mapping) else None) or event.get("EventID")
    if isinstance(event_id, Mapping):
        event_id = event_id.get("#text") or event_id.get("value")
    data = event.get("EventData", record.get("EventData", {}))
    if isinstance(data, Mapping) and "Data" in data:
        data = data["Data"]
    if isinstance(data, list):
        normalized = {}
        for item in data:
            if isinstance(item, Mapping):
                name = item.get("Name") or item.get("name")
                if name:
                    normalized[str(name)] = item.get("#text", item.get("value", item.get("Value", "")))
        data = normalized
    return (int(event_id) if str(event_id).isdigit() else None,
            data if isinstance(data, Mapping) else {})


def _records_from_json(path: Path) -> Iterable[Mapping[str, Any]]:
    """Yield event records from JSON arrays, JSON documents, or JSONL files."""
    content = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        obj = json.loads(content)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, list):
        yield from (item for item in obj if isinstance(item, Mapping))
        return
    if isinstance(obj, Mapping):
        yield obj
        return
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in {"[", "]"}:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            yield from (item for item in obj if isinstance(item, Mapping))
        elif isinstance(obj, Mapping):
            yield obj


def parse_sysmon_json(path: str | Path) -> np.ndarray:
    """Extract feature rows for consecutive 250-event windows in a capture.

    Sysmon Event IDs 1/3/8/10/11/13 map to process, network, remote-thread,
    process-access, file-create, and registry-set activity respectively.
    ZIP archives are traversed without extracting their content.
    """
    path = Path(path)
    paths: list[Path] = []
    if path.is_dir():
        paths = sorted(p for p in path.rglob("*") if p.suffix.lower() in {".json", ".jsonl"})
        archives = sorted(path.rglob("*.zip"))
    elif path.suffix.lower() == ".zip":
        archives = [path]
    else:
        paths, archives = [path], []
    all_events: list[Mapping[str, Any]] = []
    for json_path in paths:
        all_events.extend(_records_from_json(json_path))
    for archive in archives:
        with zipfile.ZipFile(archive) as zf:
            for member in zf.namelist():
                if Path(member).suffix.lower() not in {".json", ".jsonl"}:
                    continue
                with zf.open(member) as source:
                    content = source.read().decode("utf-8-sig", errors="replace")
                try:
                    obj = json.loads(content)
                except json.JSONDecodeError:
                    obj = None
                if isinstance(obj, list):
                    all_events.extend(x for x in obj if isinstance(x, Mapping))
                elif isinstance(obj, Mapping):
                    all_events.append(obj)
                else:
                    for line in content.splitlines():
                        try:
                            obj = json.loads(line.strip().rstrip(","))
                        except json.JSONDecodeError:
                            continue
                        if isinstance(obj, Mapping):
                            all_events.append(obj)
                        elif isinstance(obj, list):
                            all_events.extend(x for x in obj if isinstance(x, Mapping))
    if not all_events:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32)
    rows = []
    window_size = 250
    for offset in range(0, len(all_events), window_size):
        counts = defaultdict(float)
        for record in all_events[offset:offset + window_size]:
            event_id, data = _event_parts(record)
            if event_id == 1:
                counts["process_creation_rate"] += 1
                parent = str(data.get("ParentImage", data.get("ParentProcessName", ""))).lower()
                child = str(data.get("Image", data.get("NewProcessName", ""))).lower()
                if (any(x in parent for x in ("winword", "excel", "outlook", "wscript", "mshta")) and
                        any(x in child for x in ("powershell", "cmd.exe", "rundll32", "regsvr32"))):
                    counts["parent_child_anomaly_rate"] += 1
                if str(data.get("IntegrityLevel", "")).lower() in {"high", "system"}:
                    counts["privilege_escalation_flags"] += 1
            elif event_id == 3:
                counts["network_connection_count"] += 1
            elif event_id in {8, 10}:
                counts["privilege_escalation_flags"] += 1
            elif event_id == 11:
                counts["file_write_count"] += 1
            elif event_id == 13:
                counts["registry_write_count"] += 1
        rows.append([counts[name] for name in FEATURE_NAMES])
    return np.asarray(rows, dtype=np.float32).reshape((-1, len(FEATURE_NAMES)))


def load_sysmon_feature_rows(directory: str | Path) -> np.ndarray:
    """Read each Sysmon capture as a training sample and discard empty captures."""
    directory = Path(directory)
    rows = []
    candidates = sorted([*directory.rglob("*.json"), *directory.rglob("*.jsonl")])
    if not candidates:
        candidates = sorted(directory.rglob("*.zip"))
    # Prefer extracted files to archives when both are present, avoiding duplicates.
    for path in candidates:
        row = parse_sysmon_json(path)
        if row.size:
            rows.extend(sample for sample in row if float(sample.sum()) > 0)
    return np.asarray(rows, dtype=np.float32).reshape((-1, len(FEATURE_NAMES)))


def extract_endpoint_features(payload: Mapping[str, Any] | None, event: Any = None) -> dict[str, float]:
    """Normalize a windowed endpoint record or a single Sysmon-like event."""
    payload = dict(payload or {})
    nested = payload.get("endpoint_features")
    if isinstance(nested, Mapping):
        payload = {**payload, **nested}
    event_type = str(payload.get("event_type", getattr(event, "event_type", ""))).lower()
    process_create = int("processcreate" in event_type or "process_creation" in event_type or event_type == "process_start")
    registry_write = int("registry" in event_type and any(x in event_type for x in ("set", "write", "create")))
    file_write = int(any(x in event_type for x in ("filecreate", "file_write", "file_create")))
    network = int(any(x in event_type for x in ("networkconnect", "network_connection", "connect")))
    privilege = int(bool(payload.get("privilege_escalation", payload.get("privilege_escalation_flag", False))))
    parent = str(payload.get("parent_process", payload.get("parent_image", ""))).lower()
    child = str(payload.get("child_process", payload.get("process_name", getattr(event, "process_name", "")))).lower()
    suspicious_pair = int(bool(payload.get("parent_child_anomaly", False)) or
                          (any(x in parent for x in ("winword", "excel", "outlook", "wscript", "mshta")) and
                           any(x in child for x in ("powershell", "cmd.exe", "rundll32", "regsvr32"))))
    defaults = {
        "process_creation_rate": process_create,
        "parent_child_anomaly_rate": suspicious_pair,
        "privilege_escalation_flags": privilege,
        "registry_write_count": registry_write,
        "file_write_count": file_write,
        "network_connection_count": network,
        "cpu_percent": float(payload.get("cpu_percent", 0.0)),
        "memory_percent": float(payload.get("memory_percent", 0.0)),
        "failed_process_count": int(payload.get("failed_process_count", 0)),
    }
    aliases = {"process_creation_rate": ("process_creation_rate", "process_create_count"),
               "parent_child_anomaly_rate": ("parent_child_anomaly_rate",),
               "privilege_escalation_flags": ("privilege_escalation_flags", "privilege_escalation_count"),
               "registry_write_count": ("registry_write_count",), "file_write_count": ("file_write_count",),
               "network_connection_count": ("network_connection_count", "network_connection_count"),
               "cpu_percent": ("cpu_percent",), "memory_percent": ("memory_percent",),
               "failed_process_count": ("failed_process_count",)}
    result = {name: float(next((payload[key] for key in aliases[name] if key in payload), defaults[name]))
              for name in FEATURE_NAMES}
    values = np.asarray(list(result.values()), dtype=np.float64)
    if not np.isfinite(values).all() or (values < 0).any():
        raise ValueError("Endpoint features must be finite and non-negative")
    return result


def predict_endpoint(features: Mapping[str, Any], bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Return a calibrated [0,1] score plus named reconstruction residuals."""
    names = bundle["feature_names"]
    missing = [name for name in names if name not in features]
    if missing:
        raise ValueError(f"Endpoint features missing: {', '.join(missing)}")
    raw = np.asarray([[features[name] for name in names]], dtype=np.float32)
    if not np.isfinite(raw).all() or (raw < 0).any():
        raise ValueError("Endpoint features must be finite and non-negative")
    scaled = np.clip((raw - bundle["feature_min"]) / bundle["feature_range"], 0.0, 1.0)
    model = bundle["dae"]
    model.eval()
    with torch.no_grad():
        reconstructed = model(torch.as_tensor(scaled, dtype=torch.float32)).cpu().numpy()
    residual = np.square(scaled - reconstructed)[0]
    reconstruction_error = float(residual.mean())
    recon_score = float(np.clip((reconstruction_error - bundle["reconstruction_bounds"][0]) /
                                bundle["reconstruction_span"], 0, 1))
    if_score = float(-bundle["isolation_forest"].score_samples(scaled)[0])
    forest_score = float(np.clip((if_score - bundle["iforest_bounds"][0]) / bundle["iforest_span"], 0, 1))
    score = float(np.clip(bundle.get("score_weights", (0.6, 0.4))[0] * recon_score +
                          bundle.get("score_weights", (0.6, 0.4))[1] * forest_score, 0, 1))
    residual_by_feature = {name: float(value) for name, value in zip(names, residual)}
    top = sorted(residual_by_feature.items(), key=lambda item: item[1], reverse=True)[:5]
    return {"s_endpoint": score, "reconstruction_error": reconstruction_error,
            "reconstruction_score": recon_score, "isolation_forest_score": forest_score,
            "feature_residuals": residual_by_feature,
            "top_contributing_features": [{"feature": name, "residual": value} for name, value in top]}


def generate_synthetic_endpoint_data(n_samples: int = 1000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Generate baseline and Atomic-Red-Team-style process behavior examples."""
    rng = np.random.default_rng(seed)
    benign = np.column_stack((rng.poisson(3, n_samples), rng.binomial(1, .01, n_samples),
        rng.binomial(1, .005, n_samples), rng.poisson(1, n_samples), rng.poisson(4, n_samples),
        rng.poisson(5, n_samples), rng.normal(28, 9, n_samples).clip(0, 100),
        rng.normal(48, 12, n_samples).clip(0, 100), rng.poisson(.05, n_samples)))
    attacks = np.column_stack((rng.integers(15, 60, n_samples), rng.binomial(1, .8, n_samples),
        rng.binomial(1, .75, n_samples), rng.integers(8, 50, n_samples), rng.integers(20, 120, n_samples),
        rng.integers(20, 100, n_samples), rng.uniform(60, 100, n_samples),
        rng.uniform(70, 100, n_samples), rng.integers(1, 12, n_samples)))
    return np.vstack((benign, attacks)).astype(np.float32), np.r_[np.zeros(n_samples, dtype=int), np.ones(n_samples, dtype=int)]
