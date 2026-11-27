"""Tests for Phase 4 artifact manifest generation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.models.artifact_security import (  # noqa: E402
    MANIFEST_VERSION,
    build_manifest,
    manifest_path_for,
    sha256_file,
    write_manifest,
)


def test_build_and_write_manifest_records_required_fields(tmp_path):
    artifact = tmp_path / "demo_model.bundle.pkl"
    bundle = {
        "model_version": "demo-v1",
        "data_hash": "abc123",
        "seed": 42,
        "profile": {"name": "light", "sample_fraction": 0.15},
        "validation_metrics": {"roc_auc": 0.91},
    }
    joblib.dump(bundle, artifact)

    manifest_file = write_manifest(artifact, bundle, hmac_key="test-secret-key")
    assert manifest_file == manifest_path_for(artifact)
    assert manifest_file.is_file()

    data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert data["manifest_version"] == MANIFEST_VERSION
    assert data["artifact_filename"] == "demo_model.bundle.pkl"
    assert data["sha256"] == sha256_file(artifact)
    assert data["size_bytes"] == artifact.stat().st_size
    assert data["model_version"] == "demo-v1"
    assert data["data_hash"] == "abc123"
    assert data["git_commit"]
    assert data["config"]["seed"] == 42
    assert data["metrics"]["validation_metrics"]["roc_auc"] == 0.91
    assert data["created_at_utc"]
    assert len(data["hmac_sha256"]) == 64


def test_build_manifest_without_key_omits_hmac(tmp_path):
    artifact = tmp_path / "unsigned.pkl"
    joblib.dump({"model_version": "v0"}, artifact)
    manifest = build_manifest(artifact, {"model_version": "v0"})
    assert "hmac_sha256" not in manifest
