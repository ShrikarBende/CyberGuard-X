"""Select the previous registered signed model version."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.model_registry import rollback_model  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="Registry key, for example network_flow")
    args = parser.parse_args(argv)
    record = rollback_model(args.name)
    print(json.dumps({"model": args.name, "version": record["version"],
                      "artifact": record["artifact_path"], "sha256": record["sha256"],
                      "restart_required": True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
