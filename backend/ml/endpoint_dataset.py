"""Strict loader for explicitly labeled, already windowed Sysmon features."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import numpy as np

from ml.endpoint_branch import FEATURE_NAMES

_LABELS = {"benign": 0, "attack": 1, "0": 0, "1": 1}


def _normalize_record(record: Any, source: Path, line: int) -> tuple[list[float], int, str]:
    if not isinstance(record, dict):
        raise ValueError(f"{source.name}:{line}: each labeled window must be a JSON object")
    features = record.get("features", record)
    if not isinstance(features, dict):
        raise ValueError(f"{source.name}:{line}: features must be an object")
    missing = [name for name in FEATURE_NAMES if name not in features]
    if missing:
        raise ValueError(f"{source.name}:{line}: missing feature columns: {', '.join(missing)}")
    raw_label = record.get("label", record.get("ground_truth"))
    if raw_label is None:
        raise ValueError(f"{source.name}:{line}: explicit label is required")
    label = _LABELS.get(str(raw_label).strip().lower())
    if label is None:
        raise ValueError(f"{source.name}:{line}: label must be benign/attack or 0/1")
    capture_id = str(record.get("capture_id", "")).strip()
    if not capture_id:
        raise ValueError(f"{source.name}:{line}: capture_id is required for group-disjoint evaluation")
    try:
        values = [float(features[name]) for name in FEATURE_NAMES]
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{source.name}:{line}: features must be numeric") from exc
    vector = np.asarray(values, dtype=np.float64)
    if not np.isfinite(vector).all() or (vector < 0).any():
        raise ValueError(f"{source.name}:{line}: features must be finite and non-negative")
    return values, label, capture_id


def load_labeled_sysmon_windows(path: str | Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Load CSV or JSONL window summaries with explicit labels and capture IDs.

    CSV rows require the nine `FEATURE_NAMES`, `label`, and `capture_id` columns.
    JSONL rows use the same keys, or place the nine values under `features`.
    This loader never derives labels from the feature values or filenames.
    """
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"Labeled Sysmon windows file not found: {source}")
    records: list[dict[str, Any]] = []
    if source.suffix.lower() == ".csv":
        with source.open("r", encoding="utf-8-sig", newline="") as stream:
            records.extend(csv.DictReader(stream))
    elif source.suffix.lower() in {".jsonl", ".ndjson"}:
        with source.open("r", encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, start=1):
                if line.strip():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"{source.name}:{number}: invalid JSONL record") from exc
    else:
        raise ValueError("Labeled Sysmon windows must be a .csv, .jsonl, or .ndjson file")
    if not records:
        raise ValueError(f"No labeled Sysmon windows found in {source}")
    normalized = [_normalize_record(record, source, index + 1) for index, record in enumerate(records)]
    x = np.asarray([item[0] for item in normalized], dtype=np.float32)
    y = np.asarray([item[1] for item in normalized], dtype=np.int64)
    groups = [item[2] for item in normalized]
    return x, y, groups
