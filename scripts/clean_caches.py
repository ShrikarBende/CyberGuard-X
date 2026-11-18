#!/usr/bin/env python3
"""List removable project cache artifacts; pass --yes to delete them."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND = PROJECT_ROOT / "backend"


def _directory_size(path: Path) -> int:
    total = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
        for filename in files:
            item = Path(current) / filename
            try:
                if not item.is_symlink():
                    total += item.stat().st_size
            except OSError:
                pass
    return total


def _inside_project(path: Path) -> bool:
    try:
        path.resolve().relative_to(PROJECT_ROOT)
        return True
    except (OSError, ValueError):
        return False


def collect_targets() -> list[tuple[Path, str]]:
    targets: dict[Path, str] = {}
    parquet_cache = BACKEND / "datasets" / "cache"
    if parquet_cache.is_dir():
        for path in parquet_cache.glob("*.parquet"):
            name = path.name
            current = name.endswith(".clean-v4.parquet") or name.endswith("_dedup-v4.parquet")
            if not current:
                targets[path] = "old Parquet cache version"
                metadata = path.with_suffix(".json")
                if metadata.is_file():
                    targets[metadata] = "metadata for old Parquet cache version"

    score_dir = BACKEND / "ml" / "evaluation" / "results" / "scores"
    if score_dir.is_dir():
        for path in score_dir.glob("*.npz"):
            targets[path] = "saved evaluation score array"

    excluded = {".git", "node_modules", ".venv", "venv"}
    for current, dirs, _files in os.walk(PROJECT_ROOT, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if name not in excluded and not (Path(current) / name).is_symlink()]
        for dirname in list(dirs):
            if dirname in {"__pycache__", ".pytest_cache"}:
                path = Path(current) / dirname
                if _inside_project(path):
                    targets[path] = "Python bytecode cache" if dirname == "__pycache__" else "pytest cache"
                dirs.remove(dirname)
    return sorted(targets.items(), key=lambda item: str(item[0]).casefold())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes", action="store_true", help="Delete the listed cache artifacts")
    args = parser.parse_args()
    targets = collect_targets()
    total = 0
    if not targets:
        print("No eligible cache artifacts found.")
        return 0

    for path, reason in targets:
        size = _directory_size(path) if path.is_dir() else path.stat().st_size
        total += size
        print(f"{'DELETE' if args.yes else 'DRY RUN'}\t{size / (1024 * 1024):9.2f} MiB\t{reason}\t{path.relative_to(PROJECT_ROOT)}")
        if args.yes:
            if not _inside_project(path):
                raise RuntimeError(f"Refusing to remove a path outside the project: {path}")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)

    print(f"Total eligible: {total / (1024 * 1024):.2f} MiB across {len(targets)} paths.")
    if not args.yes:
        print("Dry run only. Re-run with --yes to delete exactly these paths.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
