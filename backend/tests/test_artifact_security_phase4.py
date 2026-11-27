import json
import joblib
import pytest

from ml import artifact_security, model_registry

TEST_KEY = "test-only-hmac-key-0123456789abcdef"


def test_signed_artifact_verifies_before_joblib_load(tmp_path, monkeypatch):
    artifact = tmp_path / "model.joblib"
    joblib.dump({"model_version": "fixture-v1"}, artifact)
    manifest = artifact_security.sign_artifact(
        artifact, TEST_KEY, model_version="fixture-v1", dataset_hash="fixture-hash",
        metrics={"macro_f1": 0.5},
    )
    assert manifest["sha256"]
    assert artifact_security.load_verified_joblib(artifact, TEST_KEY)["model_version"] == "fixture-v1"

    called = []
    monkeypatch.setattr(artifact_security.joblib, "load", lambda *_args, **_kwargs: called.append(True))
    artifact.write_bytes(artifact.read_bytes() + b"tamper")
    with pytest.raises(artifact_security.ArtifactVerificationError, match="SHA-256"):
        artifact_security.load_verified_joblib(artifact, TEST_KEY)
    assert called == []


@pytest.mark.parametrize("key,manifest_mutation", [
    (None, None), ("wrong-key-value-0123456789abcdef", None),
    (TEST_KEY, {"hmac_sha256": "not-a-signature"}),
    (TEST_KEY, {"artifact": "other.joblib"}),
])
def test_missing_or_invalid_artifact_authentication_fails_closed(tmp_path, key, manifest_mutation):
    artifact = tmp_path / "flow.pkl"
    joblib.dump({"model_version": "fixture"}, artifact)
    if key is not None:
        artifact_security.sign_artifact(artifact, TEST_KEY)
    if manifest_mutation:
        sidecar = artifact_security.manifest_path(artifact)
        manifest = json.loads(sidecar.read_text(encoding="utf-8"))
        manifest.update(manifest_mutation)
        sidecar.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(artifact_security.ArtifactVerificationError):
        artifact_security.load_verified_joblib(artifact, key)


def test_unsigned_and_malformed_manifests_fail_before_deserialization(tmp_path, monkeypatch):
    artifact = tmp_path / "bundle.pkl"
    joblib.dump({"model_version": "fixture"}, artifact)
    sidecar = artifact_security.manifest_path(artifact)
    sidecar.write_text("{broken", encoding="utf-8")
    called = []
    monkeypatch.setattr(artifact_security.joblib, "load", lambda *_args, **_kwargs: called.append(True))
    with pytest.raises(artifact_security.ArtifactVerificationError, match="malformed"):
        artifact_security.load_verified_joblib(artifact, TEST_KEY)
    assert called == []


def test_model_registry_records_metadata_and_rolls_back_to_previous_signed_version(tmp_path, monkeypatch):
    monkeypatch.setattr(model_registry, "BACKEND_ROOT", tmp_path)
    registry_path = tmp_path / "models" / "registry.json"
    older = tmp_path / "saved_models" / "flow-v1.pkl"
    newer = tmp_path / "saved_models" / "flow-v2.pkl"
    older.parent.mkdir(parents=True)
    older.write_bytes(b"older")
    newer.write_bytes(b"newer")
    for path, version, digest in ((older, "same-v1", "a" * 64), (newer, "same-v1", "b" * 64)):
        model_registry.register_model("flow", path, {
            "model_version": version, "sha256": digest, "dataset_hash": f"data-{version}",
            "git_commit": "c" * 40, "metrics": {"f1": 0.7}, "hmac_sha256": "d" * 64,
        }, registry_path=registry_path)
    assert model_registry.resolve_model_path("flow", "fallback.pkl", registry_path=registry_path) == newer.resolve()
    previous = model_registry.rollback_model("flow", registry_path=registry_path)
    assert previous["artifact_path"] == "saved_models/flow-v1.pkl"
    assert previous["dataset_hash"] == "data-same-v1"
    assert model_registry.resolve_model_path("flow", "fallback.pkl", registry_path=registry_path) == older.resolve()


def test_publish_registered_version_copies_only_verified_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(model_registry, "BACKEND_ROOT", tmp_path)
    source = tmp_path / "staged.pkl"
    joblib.dump({"model_version": "flow-v1"}, source)
    artifact_security.sign_artifact(source, TEST_KEY, model_version="flow-v1", dataset_hash="data-hash")
    registry_path = tmp_path / "models" / "registry.json"
    published = artifact_security.publish_registered_version(
        source, TEST_KEY, "flow", registry_path=registry_path,
    )
    assert published.is_file()
    assert published != source
    assert artifact_security.load_verified_joblib(published, TEST_KEY)["model_version"] == "flow-v1"
    assert model_registry.resolve_model_path("flow", "fallback", registry_path=registry_path) == published


def test_registry_rejects_artifacts_outside_backend_root(tmp_path):
    outside = tmp_path / "outside.pkl"
    outside.write_bytes(b"x")
    with pytest.raises(ValueError, match="inside the backend"):
        model_registry.register_model("flow", outside, {"sha256": "a" * 64})
