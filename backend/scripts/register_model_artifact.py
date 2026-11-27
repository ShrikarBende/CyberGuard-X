"""Sign and register a model artifact using MODEL_ARTIFACT_HMAC_KEY."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings  # noqa: E402
from ml.artifact_security import (manifest_path, publish_registered_version, sign_artifact,
                                  verify_artifact_bytes)  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--name", required=True, help="Registry key, for example network_flow")
    parser.add_argument("--version", required=True)
    parser.add_argument("--dataset-hash")
    parser.add_argument("--metrics-json", type=Path)
    parser.add_argument("--replace-manifest", action="store_true")
    args = parser.parse_args(argv)
    if not settings.MODEL_ARTIFACT_HMAC_KEY:
        parser.error("MODEL_ARTIFACT_HMAC_KEY must be configured; its value is never printed")
    metrics = {}
    if args.metrics_json:
        try:
            metrics = json.loads(args.metrics_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            parser.error("metrics JSON file is unreadable or malformed")
        if not isinstance(metrics, dict):
            parser.error("metrics JSON must contain an object")
    artifact = args.artifact
    sidecar = manifest_path(artifact)
    if sidecar.exists() and not args.replace_manifest:
        manifest = verify_artifact_bytes(artifact, artifact.read_bytes(), settings.MODEL_ARTIFACT_HMAC_KEY)
    else:
        manifest = sign_artifact(
            artifact, settings.MODEL_ARTIFACT_HMAC_KEY,
            model_version=args.version, dataset_hash=args.dataset_hash,
            metrics=metrics, overwrite=args.replace_manifest,
        )
    version_path = publish_registered_version(artifact, settings.MODEL_ARTIFACT_HMAC_KEY, args.name)
    print(json.dumps({"model": args.name, "version": manifest["model_version"],
                      "artifact": version_path.as_posix(), "sha256": manifest["sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
