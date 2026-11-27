"""Freeze the CICIDS2017 whole-session final holdout manifest (one-time command)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.evaluation.holdout import MANIFEST_PATH, create_frozen_manifest  # noqa: E402


def main() -> int:
    try:
        manifest = create_frozen_manifest()
    except FileExistsError:
        raise SystemExit(f"Refusing to replace frozen manifest: {MANIFEST_PATH}") from None
    print(json.dumps({
        "manifest_path": str(MANIFEST_PATH),
        "dataset_sha256": manifest["dataset_sha256"],
        "holdout_source_files": manifest["holdout_source_files"],
        "development_source_count": len(manifest["development_source_files"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
