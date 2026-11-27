"""One-time CLI to inspect and HMAC-sign existing model bundles in saved_models/."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import joblib

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.models.artifact_security import (  # noqa: E402
    HMAC_ENV_VAR,
    manifest_path_for,
    sha256_file,
    write_manifest,
)


def sign_models_in_dir(models_dir: Path, hmac_key: str) -> list[dict]:
    if not hmac_key:
        raise SystemExit(
            f"Error: {HMAC_ENV_VAR} is not set. Export {HMAC_ENV_VAR} in your environment before signing."
        )
    if not models_dir.is_dir():
        raise SystemExit(f"Error: models directory does not exist: {models_dir}")

    artifacts = sorted(
        p for p in models_dir.iterdir()
        if p.is_file() and (p.name.endswith(".pkl") or p.name.endswith(".joblib"))
    )
    if not artifacts:
        print(f"No .pkl or .joblib artifacts found in {models_dir}")
        return []

    signed = []
    for artifact in artifacts:
        sha = sha256_file(artifact)
        bundle = joblib.load(artifact)
        manifest_path = write_manifest(artifact, bundle, hmac_key=hmac_key)
        version = bundle.get("model_version", "unknown") if isinstance(bundle, dict) else "unknown"
        signed.append({
            "artifact": artifact.name,
            "model_version": version,
            "sha256": sha,
            "manifest": manifest_path.name,
        })
        print(f"[signed] {artifact.name} (version={version}, sha256={sha[:12]}...) -> {manifest_path.name}")
    return signed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=BACKEND / "saved_models",
        help="Directory containing saved .pkl / .joblib bundles (default: backend/saved_models)",
    )
    args = parser.parse_args()
    key = os.environ.get(HMAC_ENV_VAR, "")
    sign_models_in_dir(args.models_dir.resolve(), key)


if __name__ == "__main__":
    main()
