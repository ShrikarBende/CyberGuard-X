"""Model artifact manifest, SHA-256 integrity, and HMAC-SHA256 verification."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib

logger = logging.getLogger(__name__)

MANIFEST_VERSION = 1
HMAC_ENV_VAR = "ARTIFACT_HMAC_KEY"
ALLOW_UNSIGNED_ENV_VAR = "ALLOW_UNSIGNED_MODELS"


class ArtifactSecurityError(RuntimeError):
    """Raised when a model artifact fails manifest, hash, or HMAC verification."""


def manifest_path_for(artifact_path: Path | str) -> Path:
    """Return the companion manifest path stored beside an artifact."""
    path = Path(artifact_path)
    return path.with_name(f"{path.name}.manifest.json")


def sha256_file(path: Path | str) -> str:
    """Compute hex SHA-256 digest of a file."""
    target = Path(path)
    digest = hashlib.sha256()
    with target.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_git_commit(repo_root: Path | None = None) -> str:
    """Return HEAD git commit hash or 'unknown' if unavailable."""
    root = repo_root or Path(__file__).resolve().parents[3]
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _json_safe(value: Any) -> Any:
    """Convert numpy/Path/scalar values into JSON-serializable primitives."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if hasattr(value, "tolist"):
        return _json_safe(value.tolist())
    if hasattr(value, "item"):
        return _json_safe(value.item())
    return str(value)


def extract_bundle_metadata(bundle: Any) -> dict[str, Any]:
    """Extract version, data hash, config, and metrics from a model bundle dict."""
    if not isinstance(bundle, dict):
        return {"model_version": "unknown", "data_hash": "unknown", "config": {}, "metrics": {}}
    model_version = str(bundle.get("model_version") or "unknown")
    data_hash = str(
        bundle.get("data_hash")
        or bundle.get("training_source")
        or "unknown"
    )
    config_keys = (
        "profile", "seed", "split_type", "training_parameters",
        "training_scope", "training_source", "label_provenance",
        "calibration_method", "class_weight", "sequence_length",
        "node_feature_dim", "edge_feature_dim", "score_name",
        "open_set_validation_specificity_target", "decision_threshold",
        "tau", "feedback_samples_used",
    )
    config = {k: _json_safe(bundle[k]) for k in config_keys if k in bundle}
    metrics_keys = (
        "validation_metrics", "labeled_endpoint_evaluation",
        "evaluation_json_path", "class_balance", "train_score_quantiles",
        "training_rows", "validation_rows", "positive_rows",
    )
    metrics = {k: _json_safe(bundle[k]) for k in metrics_keys if k in bundle}
    return {
        "model_version": model_version,
        "data_hash": data_hash,
        "config": config,
        "metrics": metrics,
    }


def _canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_manifest_hmac(manifest: dict[str, Any], key: str) -> str:
    """Compute HMAC-SHA256 hex signature over canonical manifest fields."""
    if not key:
        raise ArtifactSecurityError(f"{HMAC_ENV_VAR} must be non-empty to sign or verify manifests")
    return hmac.new(key.encode("utf-8"), _canonical_manifest_bytes(manifest), hashlib.sha256).hexdigest()


def build_manifest(
    artifact_path: Path | str,
    bundle: dict[str, Any] | None = None,
    *,
    hmac_key: str | None = None,
    git_commit: str | None = None,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    """Build a manifest dictionary for an existing artifact file."""
    target = Path(artifact_path)
    if not target.is_file():
        raise FileNotFoundError(f"Artifact file not found: {target}")
    meta = extract_bundle_metadata(bundle) if bundle is not None else {
        "model_version": "unknown", "data_hash": "unknown", "config": {}, "metrics": {},
    }
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "artifact_filename": target.name,
        "sha256": sha256_file(target),
        "size_bytes": int(target.stat().st_size),
        "model_version": meta["model_version"],
        "data_hash": meta["data_hash"],
        "git_commit": git_commit or current_git_commit(),
        "config": meta["config"],
        "metrics": meta["metrics"],
        "created_at_utc": created_at_utc or datetime.now(timezone.utc).isoformat(),
    }
    if hmac_key:
        manifest["hmac_sha256"] = compute_manifest_hmac(manifest, hmac_key)
    return manifest


def write_manifest(
    artifact_path: Path | str,
    bundle: dict[str, Any] | None = None,
    *,
    hmac_key: str | None = None,
    manifest_path: Path | None = None,
) -> Path:
    """Write a manifest JSON file atomically beside the artifact."""
    target = Path(artifact_path)
    dest = manifest_path or manifest_path_for(target)
    manifest = build_manifest(target, bundle, hmac_key=hmac_key)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, dest)
    return dest
