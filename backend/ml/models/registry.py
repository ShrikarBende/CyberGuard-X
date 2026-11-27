"""Model Registry: tracks operational readiness, version history, metrics, active pointers, and rollback."""
from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from app.core.config import settings
from ml.models.artifact_security import (
    manifest_path_for,
    sha256_file,
    verify_manifest,
)

SAVED_MODELS_DIR = Path(settings.SAVED_MODELS_DIR).resolve()
MODEL_BUNDLE_PATH = Path(settings.MODEL_BUNDLE_PATH)
DEFAULT_REGISTRY_PATH = SAVED_MODELS_DIR / "registry.json"


def get_models_status() -> Dict[str, Any]:
    """Inspect availability of the live real-CICIDS2017 model bundle."""
    bundle_path = MODEL_BUNDLE_PATH
    models = {
        "cicids2017_lightgbm": {
            "name": "CICIDS2017 LightGBM Flow Classifier",
            "file": str(bundle_path),
            "is_trained": bundle_path.is_file(),
            "target": "Known network flow classes (CICIDS2017)",
        }
    }
    all_trained = all(m["is_trained"] for m in models.values())
    return {
        "models": models,
        "all_models_trained": all_trained,
        "saved_models_dir": str(SAVED_MODELS_DIR),
        "model_bundle_path": str(bundle_path),
        "status": "ready" if all_trained else "model_bundle_missing",
    }


def _load_registry(registry_path: Path) -> dict[str, Any]:
    if not registry_path.is_file():
        return {"schema_version": 1, "active": {}, "versions": {}}
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid registry JSON in {registry_path}")
    data.setdefault("schema_version", 1)
    data.setdefault("active", {})
    data.setdefault("versions", {})
    return data


def _write_registry(registry_path: Path, data: dict[str, Any]) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = registry_path.with_name(f".{registry_path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, registry_path)


def register_version(
    model_name: str,
    artifact_path: Path | str,
    *,
    version_id: str | None = None,
    metrics: dict[str, Any] | None = None,
    activate: bool = True,
    registry_path: Path | None = None,
    hmac_key: str | None = None,
    allow_unsigned: bool | None = None,
) -> dict[str, Any]:
    """Verify artifact signature, record version metadata & metrics, and optionally activate."""
    target = Path(artifact_path)
    manifest = verify_manifest(target, hmac_key=hmac_key, allow_unsigned=allow_unsigned)
    sha = manifest["sha256"] if manifest else sha256_file(target)
    model_version = (manifest or {}).get("model_version", "unknown")
    reg_path = registry_path or DEFAULT_REGISTRY_PATH
    reg = _load_registry(reg_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    vid = version_id or f"{model_version}_{stamp}_{sha[:8]}"
    entry = {
        "version_id": vid,
        "model_version": model_version,
        "artifact_path": str(target.resolve()),
        "manifest_path": str(manifest_path_for(target).resolve()),
        "sha256": sha,
        "metrics": metrics if metrics is not None else (manifest or {}).get("metrics", {}),
        "registered_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    history = reg["versions"].setdefault(model_name, [])
    history.append(entry)
    if activate:
        reg["active"][model_name] = vid
    _write_registry(reg_path, reg)
    return entry


def rollback_version(
    model_name: str,
    target_version_id: str | None = None,
    *,
    active_target_path: Path | str | None = None,
    registry_path: Path | None = None,
    hmac_key: str | None = None,
    allow_unsigned: bool | None = None,
) -> dict[str, Any]:
    """
    Verify the target version's manifest/signature and roll back the active pointer
    (and optionally copy the verified artifact + manifest to active_target_path).
    """
    reg_path = registry_path or DEFAULT_REGISTRY_PATH
    reg = _load_registry(reg_path)
    history = reg.get("versions", {}).get(model_name, [])
    if not history:
        raise ValueError(f"No registered versions found for model '{model_name}'")

    current_active = reg.get("active", {}).get(model_name)
    chosen: dict[str, Any] | None = None
    if target_version_id:
        for item in history:
            if item.get("version_id") == target_version_id:
                chosen = item
                break
        if chosen is None:
            raise ValueError(f"Version '{target_version_id}' not found for model '{model_name}'")
    else:
        if len(history) < 2:
            raise ValueError(f"No previous version available to roll back for model '{model_name}'")
        for item in reversed(history):
            if item.get("version_id") != current_active:
                chosen = item
                break
        if chosen is None:
            raise ValueError(f"No distinct previous version available for model '{model_name}'")

    chosen_artifact = Path(chosen["artifact_path"])
    chosen_manifest = Path(chosen["manifest_path"]) if chosen.get("manifest_path") else None

    # Must verify signature BEFORE activating or copying
    verify_manifest(
        chosen_artifact,
        hmac_key=hmac_key,
        allow_unsigned=allow_unsigned,
        manifest_path=chosen_manifest,
    )

    if active_target_path is not None:
        dest = Path(active_target_path)
        dest_manifest = manifest_path_for(dest)
        tmp_bundle = dest.with_name(f".{dest.name}.rollback.{os.getpid()}.tmp")
        shutil.copy2(chosen_artifact, tmp_bundle)
        os.replace(tmp_bundle, dest)
        if chosen_manifest and chosen_manifest.is_file():
            tmp_manifest = dest_manifest.with_name(f".{dest_manifest.name}.rollback.{os.getpid()}.tmp")
            shutil.copy2(chosen_manifest, tmp_manifest)
            os.replace(tmp_manifest, dest_manifest)

    reg["active"][model_name] = chosen["version_id"]
    _write_registry(reg_path, reg)
    return {
        "model_name": model_name,
        "previous_version_id": current_active,
        "active_version_id": chosen["version_id"],
        "artifact_path": str(chosen_artifact),
    }


def get_registry_summary(registry_path: Path | None = None) -> dict[str, Any]:
    """Return active pointers, version history, and metrics from the registry."""
    reg_path = registry_path or DEFAULT_REGISTRY_PATH
    return _load_registry(reg_path)
