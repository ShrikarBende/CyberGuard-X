"""Atomic background retraining API behavior."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import joblib
import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.api import endpoints
from app.detection import engine as detection_engine
from ml.training import train_final as trainer


def _wait_for_job(job_id: str):
    deadline = time.time() + 5
    while time.time() < deadline:
        status = endpoints.get_retrain_status(job_id)
        if status["status"] != "running":
            return status
        time.sleep(0.01)
    raise AssertionError("retraining background job did not finish")


def test_failed_retrain_keeps_existing_bundle(tmp_path, monkeypatch):
    target = tmp_path / "medium.bundle.pkl"
    target.write_bytes(b"old-good-bundle")
    monkeypatch.setattr(trainer, "MEDIUM_ARTIFACT_PATH", target)
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", target)

    def fail_training(profile, output_path):
        raise RuntimeError("synthetic training failure")

    monkeypatch.setattr(trainer, "train_final", fail_training)
    started = endpoints.retrain_model(endpoints.RetrainRequest(profile="medium"))
    status = _wait_for_job(started["job_id"])
    assert status["status"] == "failed"
    assert target.read_bytes() == b"old-good-bundle"


def test_successful_retrain_atomically_installs_profile_artifact(tmp_path, monkeypatch):
    target = tmp_path / "light.bundle.pkl"
    target.write_bytes(b"previous-bundle")
    monkeypatch.setattr(trainer, "ARTIFACT_PATH", target)
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", target)
    monkeypatch.setattr(detection_engine, "_MODEL_BUNDLE_CACHE", {"model_version": "previous"})

    def fake_training(profile, output_path):
        joblib.dump({"model_version": "new-light"}, output_path)
        return output_path

    monkeypatch.setattr(trainer, "train_final", fake_training)
    started = endpoints.retrain_model(endpoints.RetrainRequest(profile="light"))
    status = _wait_for_job(started["job_id"])
    assert status["status"] == "completed"
    assert joblib.load(target)["model_version"] == "new-light"
    assert detection_engine._MODEL_BUNDLE_CACHE["model_version"] == "new-light"
