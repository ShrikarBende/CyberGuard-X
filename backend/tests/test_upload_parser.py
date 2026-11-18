"""Regression tests for strict, batched upload ingestion."""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database.session import Base
from app.detection import engine as detection_engine
from app.ingestion.parser import process_uploaded_log_file
from app.models import entities  # noqa: F401
from app.models.entities import DetectionResult, SecurityEvent


@pytest.fixture
def db_session():
    test_engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=test_engine)
    factory = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    with factory() as db:
        yield db
    test_engine.dispose()


def _csv(rows, headers=("timestamp", "event_type", "bytes_transferred")):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def test_bad_timestamp_is_rejected_without_fallback(db_session, monkeypatch):
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", Path("missing.bundle"))
    payload = _csv([
        {"timestamp": "not-a-date", "event_type": "login", "bytes_transferred": "1"},
        {"timestamp": "2026-01-02T03:04:05.123Z", "event_type": "login", "bytes_transferred": "2"},
    ])
    report = process_uploaded_log_file("events.csv", payload, db_session)
    assert report["rows_read"] == 2
    assert report["inserted"] == 1
    assert report["rejected"]["count"] == 1
    assert report["rejected"]["examples"][0]["row_number"] == 2
    assert "timestamp" in report["rejected"]["examples"][0]["reason"]


def test_bad_numeric_rejects_only_its_row(db_session, monkeypatch):
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", Path("missing.bundle"))
    report = process_uploaded_log_file("events.csv", _csv([
        {"timestamp": "2026-01-02T03:04:05Z", "event_type": "flow", "bytes_transferred": "many"},
        {"timestamp": "2026-01-02T03:04:06+00:00", "event_type": "flow", "bytes_transferred": "42"},
    ]), db_session)
    assert report["inserted"] == 1
    assert report["rejected"]["count"] == 1
    assert "bytes_transferred" in report["rejected"]["examples"][0]["reason"]


def test_duplicates_in_file_and_database_are_skipped(db_session, monkeypatch):
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", Path("missing.bundle"))
    row = {"timestamp": "2026-01-02T03:04:05Z", "event_type": "login", "bytes_transferred": "4"}
    payload = _csv([row, row])
    first = process_uploaded_log_file("events.csv", payload, db_session)
    second = process_uploaded_log_file("events.csv", _csv([row]), db_session)
    assert first["inserted"] == 1 and first["duplicates"] == 1
    assert second["inserted"] == 0 and second["duplicates"] == 1
    assert db_session.query(SecurityEvent).count() == 1


def test_uppercase_json_extension_and_iso_offset(db_session, monkeypatch):
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", Path("missing.bundle"))
    payload = json.dumps({"timestamp": "2026-01-02T03:04:05.12+05:30", "event_type": "login"}).encode()
    report = process_uploaded_log_file("EVENTS.JSON", payload, db_session)
    assert report["inserted"] == 1
    assert db_session.query(SecurityEvent).one().timestamp is not None


def test_cicids_csv_is_scored_in_one_batch(db_session, monkeypatch):
    if not detection_engine.MODEL_BUNDLE_PATH.is_file():
        pytest.skip(
            "Requires the CICIDS model bundle, which is not checked into the repository."
        )
    bundle = detection_engine.load_model_bundle()
    monkeypatch.setattr(detection_engine, "load_model_bundle", lambda: bundle)
    headers = ["Timestamp", *bundle["feature_names"]]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for index in range(3):
        row = {name: "1" for name in bundle["feature_names"]}
        row["Timestamp"] = f"2026-01-02T03:04:0{index}Z"
        writer.writerow(row)
    report = process_uploaded_log_file("flows.csv", output.getvalue().encode(), db_session, detect=True)
    assert report["inserted"] == 3
    assert sum(report["detection_counts"].values()) == 3
    assert db_session.query(DetectionResult).count() == 3


def test_upload_endpoint_enforces_413_size_limit(db_session, monkeypatch):
    from fastapi import HTTPException
    from app.api import endpoints
    from app.core.config import settings

    class FakeUpload:
        filename = "events.csv"

        async def read(self, _size):
            return b"x" * 10

    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 0)
    coroutine = endpoints.upload_log_file(FakeUpload(), False, db_session)
    with pytest.raises(HTTPException) as error:
        coroutine.send(None)
    assert error.value.status_code == 413
