"""Create and restore integrity-checked SQLite backups using the online backup API."""
from __future__ import annotations

import argparse
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile


def integrity_check(path: Path) -> None:
    with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=30)) as db:
        result = db.execute("PRAGMA integrity_check").fetchone()
    if not result or result[0] != "ok":
        raise RuntimeError(f"SQLite integrity check failed for {path}: {result!r}")


def online_copy(source: Path, temporary: Path) -> None:
    with closing(sqlite3.connect(source, timeout=30)) as src, closing(sqlite3.connect(temporary, timeout=30)) as dst:
        src.backup(dst, pages=256, sleep=0.05)


def run(mode: str, source: Path, destination: Path, verify: bool, overwrite: bool) -> None:
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if source == destination:
        raise ValueError("Source and destination must be different files")
    if not source.is_file():
        raise FileNotFoundError(f"Source SQLite file does not exist: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if mode == "restore" and destination.exists() and not overwrite:
        raise FileExistsError("Restore destination exists; pass --overwrite after stopping the backend")
    if mode == "restore" and any(Path(str(destination) + suffix).exists() for suffix in ("-wal", "-shm")):
        raise RuntimeError("Restore destination has WAL/SHM sidecars; stop all writers and remove stale sidecars before restoring")
    if verify:
        integrity_check(source)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        online_copy(source, temporary)
        if verify:
            integrity_check(temporary)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--backup", metavar="LIVE_DB", help="Online-copy this live SQLite database")
    modes.add_argument("--restore", metavar="BACKUP_DB", help="Restore from this SQLite backup (stop writers first)")
    parser.add_argument("--to", required=True, metavar="PATH", help="Backup or restore destination")
    parser.add_argument("--verify", action="store_true", help="Run PRAGMA integrity_check before and after copying")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing an existing restore destination")
    args = parser.parse_args(argv)
    try:
        mode = "backup" if args.backup else "restore"
        source = Path(args.backup or args.restore)
        run(mode, source, Path(args.to), args.verify, args.overwrite)
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        print(f"sqlite backup/restore failed: {exc}", file=sys.stderr)
        return 2
    print(f"{mode} complete: {Path(args.to).expanduser().resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
