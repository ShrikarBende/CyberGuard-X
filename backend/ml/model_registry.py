"""Small JSON registry for signed model versions and rollback selection."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = BACKEND_ROOT / "models" / "registry.json"


def _read(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema_version": 1, "models": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Model registry is unreadable or malformed") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not isinstance(value.get("models"), dict):
        raise ValueError("Model registry has an unsupported structure")
    return value


def _write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def register_model(model_name: str, artifact_path: str | Path, manifest: Mapping[str, Any],
                   *, registry_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(artifact_path).resolve()
    try:
        relative = path.relative_to(BACKEND_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("Registered model artifacts must be inside the backend directory") from exc
    version = str(manifest.get("model_version") or "unrecorded")
    record = {
        "version": version,
        "artifact_path": relative,
        "sha256": manifest.get("sha256"),
        "dataset_hash": manifest.get("dataset_hash"),
        "git_commit": manifest.get("git_commit"),
        "metrics": dict(manifest.get("metrics") or {}),
        "hmac_sha256": manifest.get("hmac_sha256"),
    }
    destination = Path(registry_path) if registry_path is not None else REGISTRY_PATH
    registry = _read(destination)
    item = registry["models"].setdefault(model_name, {"active_sha256": None, "versions": []})
    versions = item["versions"]
    versions[:] = [entry for entry in versions
                   if not (entry.get("version") == version and entry.get("sha256") == record["sha256"])]
    versions.append(record)
    item["active_sha256"] = record["sha256"]
    _write(destination, registry)
    return record


def resolve_model_path(model_name: str, fallback_path: str | Path,
                       *, registry_path: str | Path | None = None) -> Path:
    """Resolve the active signed version, or the configured path before registration."""
    registry = _read(Path(registry_path) if registry_path is not None else REGISTRY_PATH)
    model = registry["models"].get(model_name)
    if not model:
        return Path(fallback_path)
    digest = model.get("active_sha256")
    entry = next((row for row in model.get("versions", []) if row.get("sha256") == digest), None)
    if not entry or not isinstance(entry.get("artifact_path"), str):
        raise ValueError(f"Active model registry entry is invalid for {model_name}")
    candidate = (BACKEND_ROOT / entry["artifact_path"]).resolve()
    try:
        candidate.relative_to(BACKEND_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"Active model registry path is outside backend for {model_name}") from exc
    return candidate


def rollback_model(model_name: str, *, registry_path: str | Path | None = None) -> dict[str, Any]:
    """Activate the previous registered version and return its artifact record.

    Runtime model caches must be reloaded (normally by restarting the app) after
    changing the active registry version. The selected file remains HMAC-verified
    by the normal loader before use.
    """
    destination = Path(registry_path) if registry_path is not None else REGISTRY_PATH
    registry = _read(destination)
    model = registry["models"].get(model_name)
    if not model:
        raise ValueError(f"No registered model exists for {model_name}")
    versions = model.get("versions", [])
    active = model.get("active_sha256")
    active_index = next((i for i, row in enumerate(versions) if row.get("sha256") == active), None)
    if active_index is None or active_index == 0:
        raise ValueError(f"No previous version is available for {model_name}")
    selected = versions[active_index - 1]
    model["active_sha256"] = selected["sha256"]
    _write(destination, registry)
    return dict(selected)
