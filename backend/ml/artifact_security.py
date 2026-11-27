"""Integrity and authenticity checks for executable model artifacts.

Joblib/pickle data must never be deserialized until its adjacent manifest has
passed both SHA-256 and HMAC-SHA-256 verification.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping

import joblib


class ArtifactVerificationError(ValueError):
    """Raised when an artifact cannot be authenticated before deserialization."""


def _key_bytes(key: str | bytes | None) -> bytes:
    value = key.encode("utf-8") if isinstance(key, str) else key
    if not value or len(value) < 32:
        raise ArtifactVerificationError("Model artifact HMAC key is missing or shorter than 32 bytes")
    return value


def manifest_path(artifact_path: str | Path) -> Path:
    path = Path(artifact_path)
    return path.with_name(path.name + ".manifest.json")


def _canonical_payload(manifest: Mapping[str, Any]) -> bytes:
    signed = {key: value for key, value in manifest.items() if key != "hmac_sha256"}
    try:
        return json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArtifactVerificationError("Model artifact manifest contains invalid metadata") from exc


def _git_commit() -> str | None:
    import subprocess
    root = Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                text=True, check=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if len(value) == 40 else None


def sign_artifact(artifact_path: str | Path, key: str | bytes | None, *,
                  model_version: str | None = None, dataset_hash: str | None = None,
                  git_commit: str | None = None, metrics: Mapping[str, Any] | None = None,
                  overwrite: bool = False) -> dict[str, Any]:
    """Write an authenticated sidecar; the model file itself is never rewritten."""
    path = Path(artifact_path)
    secret = _key_bytes(key)
    if path.is_symlink() or not path.is_file():
        raise ArtifactVerificationError("Model artifact must be a regular existing file")
    sidecar = manifest_path(path)
    if sidecar.exists() and not overwrite:
        raise ArtifactVerificationError("Model artifact manifest already exists")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ArtifactVerificationError("Model artifact could not be read") from exc
    manifest = {
        "schema_version": 1,
        "artifact": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "model_version": str(model_version or "unrecorded"),
        "dataset_hash": str(dataset_hash) if dataset_hash is not None else None,
        "git_commit": git_commit or _git_commit(),
        "metrics": dict(metrics or {}),
    }
    manifest["hmac_sha256"] = hmac.new(secret, _canonical_payload(manifest), hashlib.sha256).hexdigest()
    payload = json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".manifest.", suffix=".tmp", dir=sidecar.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, sidecar)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return manifest


def verify_artifact_bytes(artifact_path: str | Path, data: bytes, key: str | bytes | None,
                          manifest_file: str | Path | None = None) -> dict[str, Any]:
    """Verify bytes plus metadata before an executable loader sees them."""
    path = Path(artifact_path)
    secret = _key_bytes(key)
    sidecar = Path(manifest_file) if manifest_file is not None else manifest_path(path)
    if path.is_symlink() or sidecar.is_symlink() or not sidecar.is_file():
        raise ArtifactVerificationError("Model artifact signature manifest is missing or unsafe")
    try:
        manifest = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactVerificationError("Model artifact signature manifest is unreadable or malformed") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ArtifactVerificationError("Model artifact signature manifest has an unsupported format")
    if manifest.get("artifact") != path.name:
        raise ArtifactVerificationError("Model artifact signature manifest names a different artifact")
    actual_hash = hashlib.sha256(data).hexdigest()
    declared_hash = manifest.get("sha256")
    signature = manifest.get("hmac_sha256")
    if not isinstance(declared_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", declared_hash):
        raise ArtifactVerificationError("Model artifact SHA-256 verification failed")
    if not hmac.compare_digest(actual_hash, declared_hash.lower()):
        raise ArtifactVerificationError("Model artifact SHA-256 verification failed")
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", signature):
        raise ArtifactVerificationError("Model artifact HMAC signature is missing or malformed")
    expected = hmac.new(secret, _canonical_payload(manifest), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise ArtifactVerificationError("Model artifact HMAC verification failed")
    return manifest


def load_verified_joblib(artifact_path: str | Path, key: str | bytes | None) -> Any:
    """Authenticate the exact in-memory bytes before joblib deserializes them."""
    path = Path(artifact_path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ArtifactVerificationError("Model artifact could not be read") from exc
    verify_artifact_bytes(path, data, key)
    return joblib.load(io.BytesIO(data))


def save_model_bundle(bundle: Mapping[str, Any], artifact_path: str | Path, key: str | bytes | None,
                      *, registry_name: str | None = None) -> Path:
    """Persist a trainer-produced bundle and sign it when a key is configured."""
    path = Path(artifact_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(dict(bundle), path, compress=3)
    if key:
        manifest = sign_artifact(
            path, key, model_version=bundle.get("model_version"),
            dataset_hash=bundle.get("data_hash"), metrics=bundle.get("validation_metrics") or {},
            overwrite=True,
        )
        if registry_name:
            publish_registered_version(path, key, registry_name)
    return path


def publish_registered_version(artifact_path: str | Path, key: str | bytes, model_name: str,
                               *, versions_dir: str | Path | None = None,
                               registry_path: str | Path | None = None) -> Path:
    """Copy a verified artifact into immutable version storage and activate it."""
    import re
    from ml.model_registry import BACKEND_ROOT, REGISTRY_PATH, register_model

    source = Path(artifact_path)
    if source.is_symlink() or not source.is_file():
        raise ArtifactVerificationError("Model artifact must be a regular existing file")
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise ArtifactVerificationError("Model artifact could not be read") from exc
    manifest = verify_artifact_bytes(source, data, key)
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "-", model_name).strip("-")
    if not safe_name:
        raise ValueError("Model registry name must contain letters or digits")
    # Keep the on-disk version directory and filenames short for Windows path
    # limits while retaining content-addressed immutable artifact names.
    directory = Path(versions_dir) if versions_dir else BACKEND_ROOT / "saved_models" / "v"
    directory.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix if source.suffix else ".joblib"
    destination = directory / f"{safe_name[:24]}-{manifest['sha256'][:10]}{suffix}"
    if destination.exists():
        if destination.is_symlink() or hashlib.sha256(destination.read_bytes()).hexdigest() != manifest["sha256"]:
            raise ArtifactVerificationError("Immutable model version path already contains different data")
    else:
        fd, temporary_name = tempfile.mkstemp(prefix=".model.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        finally:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
        sign_artifact(
            destination, key, model_version=manifest.get("model_version"),
            dataset_hash=manifest.get("dataset_hash"), git_commit=manifest.get("git_commit"),
            metrics=manifest.get("metrics") or {},
        )
    final_manifest = verify_artifact_bytes(destination, destination.read_bytes(), key)
    register_model(model_name, destination, final_manifest,
                   registry_path=registry_path if registry_path is not None else REGISTRY_PATH)
    return destination
