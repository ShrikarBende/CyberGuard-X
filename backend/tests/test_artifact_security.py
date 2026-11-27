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


# ---------------------------------------------------------------------------
# All 6 real bundles + per-loader-family failure-mode coverage
# ---------------------------------------------------------------------------

ALL_SIX_BUNDLES = [
    "cicids2017_medium_lightgbm.bundle.pkl",
    "cicids2017_lightgbm.bundle.pkl",
    "endpoint_behavior.bundle.pkl",
    "user_tft.bundle.pkl",
    "network_gat.bundle.pkl",
    "risk_fusion_meta.joblib",
]


def _configure_loader_target(monkeypatch, family: str, target_path: Path) -> callable:
    """Point a loader family at target_path, reset its process cache, and return its loader."""
    from app.detection import engine
    from ml import fusion_meta

    if family == "cicids":
        monkeypatch.setattr(engine, "MODEL_BUNDLE_PATH", target_path)
        monkeypatch.setattr(engine, "_MODEL_BUNDLE_CACHE", None)
        return engine.load_model_bundle
    if family == "endpoint":
        monkeypatch.setattr(engine, "ENDPOINT_BUNDLE_PATH", target_path)
        monkeypatch.setattr(engine, "_ENDPOINT_BUNDLE_CACHE", None)
        return engine.load_endpoint_bundle
    if family == "user_tft":
        monkeypatch.setattr(engine, "USER_BUNDLE_PATH", target_path)
        monkeypatch.setattr(engine, "_USER_BUNDLE_CACHE", None)
        return engine.load_user_bundle
    if family == "network_gat":
        monkeypatch.setattr(engine, "NETWORK_GAT_BUNDLE_PATH", target_path)
        monkeypatch.setattr(engine, "_NETWORK_GAT_BUNDLE_CACHE", None)
        return engine.load_network_gat_bundle
    if family == "fusion":
        monkeypatch.setattr(fusion_meta, "ARTIFACT_PATH", target_path)
        monkeypatch.setattr(fusion_meta, "_BUNDLE_CACHE", None)
        return fusion_meta.load_fusion_bundle
    raise ValueError(f"Unknown loader family: {family}")


@pytest.mark.requires_data(reason="Requires the 6 model bundles in backend/saved_models")
def test_all_six_real_bundles_load_signed_in_temp_dir(tmp_path, monkeypatch):
    """Copy all 6 bundles to a temp dir, sign with a temp key, and load via verified loaders."""
    import shutil

    saved_dir = BACKEND / "saved_models"
    missing = [name for name in ALL_SIX_BUNDLES if not (saved_dir / name).is_file()]
    if missing:
        pytest.skip(f"Missing bundles in {saved_dir}: {missing}")

    for name in ALL_SIX_BUNDLES:
        shutil.copy2(saved_dir / name, tmp_path / name)

    test_key = "temp-all-six-bundles-hmac-key"
    results = sign_models_in_dir(tmp_path, test_key)
    assert len(results) == 6

    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    monkeypatch.setenv("ARTIFACT_HMAC_KEY", test_key)

    family_map = [
        ("cicids", "cicids2017_medium_lightgbm.bundle.pkl"),
        ("cicids", "cicids2017_lightgbm.bundle.pkl"),
        ("endpoint", "endpoint_behavior.bundle.pkl"),
        ("user_tft", "user_tft.bundle.pkl"),
        ("network_gat", "network_gat.bundle.pkl"),
        ("fusion", "risk_fusion_meta.joblib"),
    ]
    for family, filename in family_map:
        loader = _configure_loader_target(monkeypatch, family, tmp_path / filename)
        loaded = loader()
        assert isinstance(loaded, dict)
        assert loaded.get("model_version"), f"Expected model_version in {filename}"


@pytest.mark.parametrize(
    "family,filename",
    [
        ("cicids", "cicids.bundle.pkl"),
        ("endpoint", "endpoint.bundle.pkl"),
        ("user_tft", "user_tft.bundle.pkl"),
        ("network_gat", "network_gat.bundle.pkl"),
        ("fusion", "risk_fusion_meta.joblib"),
    ],
)
@pytest.mark.parametrize("failure_mode", ["tampered", "wrong_key", "missing_manifest"])
def test_each_loader_family_rejects_untrusted_artifacts(
    tmp_path, monkeypatch, family: str, filename: str, failure_mode: str
):
    """Every loader family must reject tampered files, wrong keys, and missing manifests."""
    target = tmp_path / filename
    dummy_bundle = {"model_version": "v-test"}
    joblib.dump(dummy_bundle, target)
    loader = _configure_loader_target(monkeypatch, family, target)

    monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")
    valid_key = "family-test-hmac-key"

    if failure_mode == "missing_manifest":
        monkeypatch.setenv("ARTIFACT_HMAC_KEY", valid_key)
        with pytest.raises(ArtifactSecurityError, match="missing manifest"):
            loader()
    elif failure_mode == "wrong_key":
        write_manifest(target, dummy_bundle, hmac_key=valid_key)
        monkeypatch.setenv("ARTIFACT_HMAC_KEY", "wrong-hmac-key")
        with pytest.raises(ArtifactSecurityError, match="HMAC signature verification failed"):
            loader()
    elif failure_mode == "tampered":
        write_manifest(target, dummy_bundle, hmac_key=valid_key)
        monkeypatch.setenv("ARTIFACT_HMAC_KEY", valid_key)
        target.write_bytes(target.read_bytes() + b"TAMPERED")
        with pytest.raises(ArtifactSecurityError, match="SHA-256 mismatch"):
            loader()
