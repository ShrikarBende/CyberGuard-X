"""CLI for inspecting the file-based model registry and rolling back versions."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKEND = REPO / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.models.registry import (  # noqa: E402
    DEFAULT_REGISTRY_PATH,
    get_registry_summary,
    register_version,
    rollback_version,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="Show active pointers and version history")

    reg_p = sub.add_parser("register", help="Verify and register a signed model artifact")
    reg_p.add_argument("model_name")
    reg_p.add_argument("artifact_path", type=Path)
    reg_p.add_argument("--version-id", default=None)
    reg_p.add_argument("--no-activate", action="store_true")

    rb_p = sub.add_parser("rollback", help="Verify signature and roll back to a previous version")
    rb_p.add_argument("model_name")
    rb_p.add_argument("--version-id", default=None)
    rb_p.add_argument("--target-path", type=Path, default=None)

    args = parser.parse_args()
    if args.command == "list":
        print(json.dumps(get_registry_summary(args.registry), indent=2))
    elif args.command == "register":
        entry = register_version(
            args.model_name,
            args.artifact_path,
            version_id=args.version_id,
            activate=not args.no_activate,
            registry_path=args.registry,
        )
        print(json.dumps(entry, indent=2))
    elif args.command == "rollback":
        res = rollback_version(
            args.model_name,
            target_version_id=args.version_id,
            active_target_path=args.target_path,
            registry_path=args.registry,
        )
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
