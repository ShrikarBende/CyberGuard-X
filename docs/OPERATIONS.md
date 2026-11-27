# SQLite Operations

## Supported deployment boundary

The application supports SQLite. The supported Compose topology has one backend container and one Uvicorn worker (`backend/Dockerfile` starts `uvicorn ... --workers 1`). Keep one backend process/container as the only writer to a database file. Do not run multiple workers or replicas against the same SQLite file: SQLite permits many readers but serializes writers, and process-local job registries, WebSocket broadcasts, and throttles also do not coordinate across workers. The database must be on a local filesystem with reliable SQLite locking; do not put it on a network share.

`backend/app/database/session.py` configures `journal_mode=WAL`, `busy_timeout=10000` (10 seconds), `synchronous=NORMAL`, and `foreign_keys=ON` for each SQLAlchemy SQLite connection. SQLAlchemy's file-backed connection pool reuses connections; `check_same_thread=False` supports the app's threaded request environment. WAL improves reader/writer overlap but does not allow simultaneous writers. A write that remains blocked beyond the busy timeout fails. The busy timeout is a wait boundary, not a write queue or a substitute for limiting write-heavy work.

## Managing write-heavy jobs

Ingestion, replay, correlation, model/evaluation jobs, and agent-run persistence can compete for the single SQLite writer lock. Keep one backend process, avoid starting several large jobs together, and schedule bulk ingestion/replay away from other write-heavy jobs. Use short transactions and let the request/job finish before starting another bulk writer. Do not manually copy a live `.sqlite`/`.db` file with ordinary file-copy tools; the committed state may include data in the WAL sidecar.

### Local contention benchmark

Run the repeatable local synthetic workload from the repository root:

```powershell
python scripts/benchmark_sqlite_boundary.py
```

It creates a temporary WAL database, simulates ingestion, correlation, and agent-run writes from six threads inside one process (600 total transactions), checks integrity, and saves a timestamped JSON artifact under `backend/ml/evaluation/results/`. It does not open the application's database and does not emulate multiple backend processes or production traffic. The reference run `sqlite_boundary_20261127T104608Z.json` measured median write latency **1.36 ms**, p95 **10.92 ms**, **0** lock retries, **0** `database is locked` failures, 600/600 committed writes, and `integrity_check=ok` on this local environment. Treat it as a local baseline, not a production SLO.

## Backup, integrity check, and restore drill

The utility uses Python's `sqlite3.Connection.backup()` API, which takes a consistent database snapshot while WAL is active. Always use a new, timestamped backup path and store copies away from the machine/container holding the database. `--verify` checks both source and copied/restored files with `PRAGMA integrity_check`.

Create an online backup while the service is running (replace paths with the actual database and backup paths):

```powershell
python scripts/sqlite_backup_restore.py --backup backend/cyberguardx.db --to backups/cyberguardx-2026-11-27.sqlite --verify
```

For Compose, the database is `/app/data/cyberguardx.db` inside the backend container. The image includes the utility. Create the copy online inside the container, then copy the completed backup file to the host:

```powershell
docker compose exec backend python /app/scripts/sqlite_backup_restore.py --backup /app/data/cyberguardx.db --to /app/data/backups/cyberguardx-2026-11-27.sqlite --verify
docker cp cyberguardx-backend:/app/data/backups/cyberguardx-2026-11-27.sqlite backups/cyberguardx-2026-11-27.sqlite
```

To inspect integrity without making a copy, use:

```powershell
python -c "import sqlite3; c=sqlite3.connect('backups/cyberguardx-2026-11-27.sqlite'); print(c.execute('PRAGMA integrity_check').fetchone()[0]); c.close()"
```

Restore is an offline operation. Stop the backend first so no process has the destination open. Preserve the current database separately, then restore to the stopped service's database path. Existing destinations require explicit `--overwrite`; restore refuses destinations with `-wal` or `-shm` sidecars.

```powershell
docker compose stop backend
python scripts/sqlite_backup_restore.py --restore backups/cyberguardx-2026-11-27.sqlite --to backend/cyberguardx.db --verify --overwrite
python -c "import sqlite3; c=sqlite3.connect('backend/cyberguardx.db'); print(c.execute('PRAGMA integrity_check').fetchone()[0]); c.close()"
docker compose start backend
```

For Compose, after stopping the backend run the restore utility in a one-off container that mounts the same named volume, then start the service:

```powershell
docker compose run --rm --no-deps backend python /app/scripts/sqlite_backup_restore.py --restore /app/data/backups/cyberguardx-2026-11-27.sqlite --to /app/data/cyberguardx.db --verify --overwrite
docker compose start backend
```

Confirm the application health endpoint and expected records after startup. Practice this drill against a disposable copy before relying on a backup. Keep backup retention and access controls appropriate for the telemetry and analyst data stored in the database.

## Contention monitoring and scale-up criteria

The app does not currently export a dedicated SQLite lock-wait metric. Monitor backend logs for `database is locked`, track write-heavy job durations/failures, and periodically inspect the database and WAL sizes. On a copy or during a maintenance window, check WAL status with:

```powershell
python -c "import sqlite3; c=sqlite3.connect('backend/cyberguardx.db'); print(c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()); c.close()"
Get-Item backend/cyberguardx.db, backend/cyberguardx.db-wal -ErrorAction SilentlyContinue | Select-Object Name,Length
```

Treat any `database is locked` error as an incident to investigate. Investigate sustained write p95 above 1 second, repeated lock waits/retries, growing WAL that does not checkpoint, or jobs frequently exceeding their expected runtime. Reduce overlapping writers and transaction duration first. Move to a client-server database when the product needs multiple backend replicas/workers writing concurrently, persistent lock errors despite serialized jobs and the 10-second wait, or sustained write volume that cannot meet operational latency goals. Validate and plan a migration separately; do not point this SQLite-only application at a PostgreSQL URL.

## Automated verification

Run the operations tests and full backend suite from the repository root:

```powershell
python -m pytest backend/tests -v
```
