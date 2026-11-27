from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import threading

import pytest

from app.database.session import SQLITE_BUSY_TIMEOUT_MS, engine
from scripts.sqlite_backup_restore import integrity_check, run as copy_database


def test_online_backup_integrity_and_restore(tmp_path: Path):
    live = tmp_path / "live.sqlite"
    backup = tmp_path / "backup.sqlite"
    restored = tmp_path / "restored.sqlite"
    with sqlite3.connect(live) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE records(value TEXT NOT NULL)")
        db.executemany("INSERT INTO records VALUES (?)", [(str(i),) for i in range(20)])

    copy_database("backup", live, backup, verify=True, overwrite=False)
    copy_database("restore", backup, restored, verify=True, overwrite=False)
    integrity_check(restored)
    with sqlite3.connect(restored) as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 20

    with pytest.raises(FileExistsError):
        copy_database("restore", backup, restored, verify=True, overwrite=False)


def test_online_backup_is_consistent_during_wal_writes(tmp_path: Path):
    live = tmp_path / "live.sqlite"
    backup = tmp_path / "backup.sqlite"
    with sqlite3.connect(live) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("CREATE TABLE records(value INTEGER PRIMARY KEY)")

    started = threading.Event()

    def writer():
        with sqlite3.connect(live, timeout=10) as db:
            db.execute("PRAGMA busy_timeout=10000")
            for value in range(100):
                db.execute("INSERT INTO records VALUES (?)", (value,))
                db.commit()
                if value == 5:
                    started.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(writer)
        assert started.wait(2)
        copy_database("backup", live, backup, verify=True, overwrite=False)
        future.result()
    with sqlite3.connect(backup) as db:
        copied_count = db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    assert 6 <= copied_count <= 100
    integrity_check(backup)


def test_concurrent_wal_writes_complete_with_busy_timeout(tmp_path: Path):
    path = tmp_path / "concurrent.sqlite"
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("CREATE TABLE writes(value INTEGER PRIMARY KEY)")

    def write(worker: int):
        with sqlite3.connect(path, timeout=10) as db:
            db.execute("PRAGMA busy_timeout=10000")
            db.executemany("INSERT INTO writes VALUES (?)", [(worker * 100 + i,) for i in range(100)])

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(write, range(5)))
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM writes").fetchone()[0] == 500
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_restore_refuses_active_wal_sidecars(tmp_path: Path):
    backup = tmp_path / "backup.sqlite"
    destination = tmp_path / "target.sqlite"
    with sqlite3.connect(backup) as db:
        db.execute("CREATE TABLE records(value INTEGER)")
    (tmp_path / "target.sqlite-wal").touch()
    with pytest.raises(RuntimeError, match="WAL/SHM"):
        copy_database("restore", backup, destination, verify=True, overwrite=False)


def test_application_sqlite_connection_uses_documented_pragmas():
    assert SQLITE_BUSY_TIMEOUT_MS == 10_000
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar().lower() == "wal"
        assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() == SQLITE_BUSY_TIMEOUT_MS
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 1
