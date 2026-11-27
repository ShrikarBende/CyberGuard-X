"""Tests for Phase 4 file-based model registry and signature-verified rollback."""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import pytest

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.models.artifact_security import (  # noqa: E402
    ArtifactSecurityError,
    verify_and_load_joblib,
    write_manifest,
)
from ml.models.registry import (  # noqa: E402
    get_registry_summary,
    register_version,
    rollback_version,
)


def _create_version(folder: Path, name: str, version: str, key: str) -> Path:
    path = folder / name
    bundle = {"model_version": version, "validation_metrics": {"f1": 0.85}}
    joblib.dump(bundle, path)
    write_manifest(path, bundle, hmac_key=key)
    return path


def test_registry_records_versions_and_rolls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "reg-key")
    reg_path = tmp_path / "registry.json"
    live_path = tmp_path / "live.bundle.pkl"

    v1 = _create_version(tmp_path, "v1.bundle.pkl", "v1", "reg-key")
    v2 = _create_version(tmp_path, "v2.bundle.pkl", "v2", "reg-key")

    e1 = register_version("cicids", v1, version_id="ver-1", metrics={"f1": 0.81}, registry_path=reg_path)
    e2 = register_version("cicids", v2, version_id="ver-2", metrics={"f1": 0.88}, registry_path=reg_path)
    assert e1["version_id"] == "ver-1"
    assert e2["version_id"] == "ver-2"

    summary = get_registry_summary(reg_path)
    assert summary["active"]["cicids"] == "ver-2"
    assert len(summary["versions"]["cicids"]) == 2

    res = rollback_version("cicids", active_target_path=live_path, registry_path=reg_path)
    assert res["active_version_id"] == "ver-1"
    assert get_registry_summary(reg_path)["active"]["cicids"] == "ver-1"
    assert verify_and_load_joblib(live_path)["model_version"] == "v1"


def test_rollback_refuses_tampered_artifact_or_wrong_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "reg-key")
    reg_path = tmp_path / "registry.json"

    v1 = _create_version(tmp_path, "v1.bundle.pkl", "v1", "reg-key")
    v2 = _create_version(tmp_path, "v2.bundle.pkl", "v2", "reg-key")
    register_version("cicids", v1, version_id="ver-1", registry_path=reg_path)
    register_version("cicids", v2, version_id="ver-2", registry_path=reg_path)

    # Tamper with v1 before rollback
    v1.write_bytes(v1.read_bytes() + b"CORRUPT")
    with pytest.raises(ArtifactSecurityError, match="SHA-256 mismatch"):
        rollback_version("cicids", target_version_id="ver-1", registry_path=reg_path)
    assert get_registry_summary(reg_path)["active"]["cicids"] == "ver-2"

    # Wrong key also refuses
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "wrong-key")
    with pytest.raises(ArtifactSecurityError, match="HMAC signature verification failed"):
        rollback_version("cicids", target_version_id="ver-2", registry_path=reg_path)
