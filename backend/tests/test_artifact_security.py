"""Tests for Phase 4 HMAC signing, verification, and unsigned-load behavior."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import joblib
import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ml.models.artifact_security import (  # noqa: E402
    ArtifactSecurityError,
    manifest_path_for,
    verify_and_load_joblib,
    write_manifest,
)
from scripts.sign_existing_models import sign_models_in_dir  # noqa: E402


def _make_signed_bundle(tmp_path: Path, key: str = "unit-test-hmac-key") -> Path:
    artifact = tmp_path / "model.bundle.pkl"
    bundle = {"model_version": "v1.0", "data_hash": "deadbeef"}
    joblib.dump(bundle, artifact)
    write_manifest(artifact, bundle, hmac_key=key)
    return artifact


def test_valid_signed_bundle_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "unit-test-hmac-key")
    artifact = _make_signed_bundle(tmp_path, key="unit-test-hmac-key")
    loaded = verify_and_load_joblib(artifact)
    assert loaded["model_version"] == "v1.0"


def test_tampered_file_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "unit-test-hmac-key")
    artifact = _make_signed_bundle(tmp_path, key="unit-test-hmac-key")
    # Tamper with artifact bytes after signing
    artifact.write_bytes(artifact.read_bytes() + b"TAMPERED")
    with pytest.raises(ArtifactSecurityError, match="SHA-256 mismatch"):
        verify_and_load_joblib(artifact)


def test_wrong_key_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "wrong-key")
    artifact = _make_signed_bundle(tmp_path, key="unit-test-hmac-key")
    with pytest.raises(ArtifactSecurityError, match="HMAC signature verification failed"):
        verify_and_load_joblib(artifact)


def test_missing_manifest_rejected_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "unit-test-hmac-key")
    artifact = tmp_path / "unsigned.bundle.pkl"
    joblib.dump({"model_version": "v0"}, artifact)
    with pytest.raises(ArtifactSecurityError, match="missing manifest"):
        verify_and_load_joblib(artifact)


def test_truncated_manifest_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "unit-test-hmac-key")
    artifact = _make_signed_bundle(tmp_path, key="unit-test-hmac-key")
    m_path = manifest_path_for(artifact)
    m_path.write_text(m_path.read_text(encoding="utf-8")[:25], encoding="utf-8")
    with pytest.raises(ArtifactSecurityError, match="malformed or truncated"):
        verify_and_load_joblib(artifact)


def test_allow_unsigned_models_logs_loud_warning_every_load(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "true")
    monkeypatch.delenv("ARTIFACT_HMAC_KEY", raising=False)
    artifact = tmp_path / "unsigned.bundle.pkl"
    joblib.dump({"model_version": "v0"}, artifact)
    with caplog.at_level(logging.WARNING):
        loaded_1 = verify_and_load_joblib(artifact)
        loaded_2 = verify_and_load_joblib(artifact)
    assert loaded_1["model_version"] == "v0"
    assert loaded_2["model_version"] == "v0"
    warnings = [r for r in caplog.records if "SECURITY WARNING" in r.message]
    assert len(warnings) == 2


def test_allow_unsigned_models_still_rejects_tampered_file_with_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "true")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "unit-test-hmac-key")
    artifact = _make_signed_bundle(tmp_path, key="unit-test-hmac-key")
    artifact.write_bytes(artifact.read_bytes() + b"TAMPERED")
    with pytest.raises(ArtifactSecurityError, match="SHA-256 mismatch"):
        verify_and_load_joblib(artifact)


def test_sign_existing_models_cli_signs_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", "cli-test-key")
    a = tmp_path / "a.bundle.pkl"
    b = tmp_path / "b.joblib"
    joblib.dump({"model_version": "a-v1"}, a)
    joblib.dump({"model_version": "b-v1"}, b)

    results = sign_models_in_dir(tmp_path, "cli-test-key")
    assert len(results) == 2
    assert verify_and_load_joblib(a)["model_version"] == "a-v1"
    assert verify_and_load_joblib(b)["model_version"] == "b-v1"
