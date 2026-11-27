"""Create and validate a frozen, source-session holdout manifest."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ml.preprocessing.cicids_pipeline import CICIDS_FILES, DATASETS_DIR


MANIFEST_VERSION = 1
DATASET_VERSION = "CICIDS2017"
MANIFEST_PATH = Path(__file__).resolve().parent / "holdout_manifest.json"
# CICIDS2017 source CSVs contain no timestamp field. A whole source capture
# file is therefore the smallest defensible independent session group.
HOLDOUT_SOURCE_FILE = CICIDS_FILES[0]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_inventory(dataset_dir: Path = DATASETS_DIR) -> list[dict[str, str | int]]:
    records = []
    for name in CICIDS_FILES:
        path = dataset_dir / "trafficlabelling" / name
        if not path.is_file():
            raise FileNotFoundError(f"Required CICIDS2017 source file is missing: {path}")
        records.append({"file": name, "bytes": path.stat().st_size, "sha256": _sha256_file(path)})
    return records


def dataset_fingerprint(files: list[dict]) -> str:
    encoded = json.dumps({"dataset_version": DATASET_VERSION, "files": files},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def create_frozen_manifest(path: Path = MANIFEST_PATH, dataset_dir: Path = DATASETS_DIR) -> dict:
    """Create once; refuse to replace an existing holdout definition."""
    files = source_inventory(dataset_dir)
    names = [item["file"] for item in files]
    if HOLDOUT_SOURCE_FILE not in names or len(names) != len(set(names)):
        raise ValueError("CICIDS source inventory is invalid")
    payload = {
        "manifest_version": MANIFEST_VERSION,
        "dataset_version": DATASET_VERSION,
        "dataset_sha256": dataset_fingerprint(files),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "grouping": "one complete source CSV per capture session; source files have no Timestamp column",
        "holdout_selection_rule": "reserve the first source file in the checked-in CICIDS_FILES order before running development evaluation",
        "holdout_source_files": [HOLDOUT_SOURCE_FILE],
        "development_source_files": [name for name in names if name != HOLDOUT_SOURCE_FILE],
        "source_files": files,
        "holdout_policy": "The evaluation runner never parses, samples, trains on, tunes on, or scores rows from holdout_source_files.",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded)
    return payload


def load_and_validate_manifest(path: Path = MANIFEST_PATH, dataset_dir: Path = DATASETS_DIR) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("manifest_version") != MANIFEST_VERSION or payload.get("dataset_version") != DATASET_VERSION:
        raise ValueError("Unsupported frozen holdout manifest or dataset version")
    expected = [entry.get("file") for entry in payload.get("source_files", [])]
    if expected != CICIDS_FILES:
        raise ValueError("Frozen holdout source inventory differs from CICIDS_FILES")
    current = source_inventory(dataset_dir)
    if current != payload["source_files"]:
        raise ValueError("CICIDS source files differ from the frozen manifest; refusing evaluation")
    if dataset_fingerprint(current) != payload.get("dataset_sha256"):
        raise ValueError("CICIDS dataset hash differs from the frozen manifest")
    holdout = payload.get("holdout_source_files")
    development = payload.get("development_source_files")
    if (not isinstance(holdout, list) or len(holdout) != 1 or
            set(holdout) & set(development or []) or
            set(holdout) | set(development or []) != set(CICIDS_FILES)):
        raise ValueError("Frozen holdout and development source groups are invalid")
    return payload


def manifest_sha256(path: Path = MANIFEST_PATH) -> str:
    return _sha256_file(path)
