"""Controlled temporary-file SQLite contention benchmark for the single-backend boundary."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sqlite3
import statistics
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "backend" / "ml" / "evaluation" / "results"
BUSY_TIMEOUT_MS = 10_000
WORKERS = 6
WRITES_PER_WORKER = 100


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(p * len(ordered)) - 1)]


def main() -> Path:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RESULTS / f"sqlite_boundary_{run_id}.json"
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing artifact: {path}")
    RESULTS.mkdir(parents=True, exist_ok=True)
    latencies: list[float] = []
    lock = threading.Lock()
    lock_retries = 0
    locked_failures = 0
    errors: list[str] = []
    per_role = {"ingestion": 0, "correlation": 0, "agent_run_update": 0}
    start = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="cyberguardx-sqlite-bench-") as directory:
        db_path = Path(directory) / "boundary.sqlite"
        with closing(sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000)) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            db.execute("PRAGMA synchronous=NORMAL")
            db.executescript("""
                CREATE TABLE ingestion_events(id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE correlation_jobs(id INTEGER PRIMARY KEY, status TEXT NOT NULL);
                CREATE TABLE agent_runs(id INTEGER PRIMARY KEY, status TEXT NOT NULL);
            """)
        def worker(worker_id: int) -> None:
            nonlocal lock_retries, locked_failures
            role = ("ingestion", "correlation", "agent_run_update")[worker_id % 3]
            for index in range(WRITES_PER_WORKER):
                began = time.perf_counter()
                success = False
                for attempt in range(4):
                    try:
                        with closing(sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000)) as db:
                            db.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
                            db.execute("PRAGMA synchronous=NORMAL")
                            db.execute("BEGIN IMMEDIATE")
                            if role == "ingestion":
                                db.execute("INSERT INTO ingestion_events(payload) VALUES (?)", (f"{worker_id}:{index}",))
                            elif role == "correlation":
                                db.execute("INSERT INTO correlation_jobs(status) VALUES ('complete')")
                            else:
                                db.execute("INSERT INTO agent_runs(status) VALUES ('running')")
                            db.commit()
                        success = True
                        break
                    except sqlite3.OperationalError as exc:
                        if "locked" not in str(exc).lower():
                            with lock:
                                errors.append(str(exc))
                            break
                        with lock:
                            lock_retries += 1
                        if attempt == 3:
                            with lock:
                                locked_failures += 1
                        else:
                            time.sleep(0.01 * (attempt + 1))
                    except Exception as exc:
                        with lock:
                            errors.append(repr(exc))
                        break
                elapsed = (time.perf_counter() - began) * 1000
                with lock:
                    latencies.append(elapsed)
                    if success:
                        per_role[role] += 1
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(worker, i) for i in range(WORKERS)]
            for future in as_completed(futures):
                future.result()
        elapsed_s = time.perf_counter() - start
        with closing(sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_MS / 1000)) as db:
            db.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            db.execute("PRAGMA synchronous=NORMAL")
            row_counts = {name: db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                          for name in ("ingestion_events", "correlation_jobs", "agent_runs")}
            journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
            busy_timeout = db.execute("PRAGMA busy_timeout").fetchone()[0]
            synchronous = db.execute("PRAGMA synchronous").fetchone()[0]
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    artifact = {
        "artifact_schema_version": 1,
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Synthetic local SQLite workload on a temporary file; single backend process with concurrent in-process job threads; not production traffic or a multi-process/multi-host test.",
        "operating_boundary": {"backend_processes": 1, "uvicorn_workers": 1, "sqlite_wal": journal_mode.upper(),
                               "busy_timeout_ms": busy_timeout, "synchronous_pragma": synchronous,
                               "worker_threads": WORKERS, "writes_per_worker": WRITES_PER_WORKER,
                               "retry_policy": "up to 3 application retries after SQLite busy_timeout; 10/20/30ms backoff"},
        "workload": {"ingestion": "insert telemetry rows", "correlation": "insert completed correlation jobs",
                     "agent_run_update": "insert running agent-run rows", "successful_writes_by_role": per_role,
                     "row_counts": row_counts},
        "metrics": {"write_count": len(latencies), "median_write_latency_ms": statistics.median(latencies),
                    "p95_write_latency_ms": percentile(latencies, .95), "lock_retry_count": lock_retries,
                    "database_is_locked_failures": locked_failures, "other_errors": errors,
                    "duration_seconds": elapsed_s, "writes_per_second": len(latencies) / elapsed_s,
                    "integrity_check": integrity},
        "acceptance": {"zero_locked_failures": locked_failures == 0,
                       "all_writes_committed": sum(per_role.values()) == WORKERS * WRITES_PER_WORKER,
                       "integrity_ok": integrity == "ok"},
    }
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    print(main())
