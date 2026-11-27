"""Tests for fusion retraining feedback deduplication and logging."""
from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from app.api import endpoints as endpoints_mod
from app.api.endpoints import _build_fusion_feedback_samples


@pytest.fixture
def capture_endpoint_logs():
    records: list[str] = []

    class _ListHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = _ListHandler()
    handler.setLevel(logging.INFO)
    prev_level = endpoints_mod.logger.level
    prev_disabled = endpoints_mod.logger.disabled
    endpoints_mod.logger.disabled = False
    endpoints_mod.logger.addHandler(handler)
    if prev_level == logging.NOTSET or prev_level > logging.INFO:
        endpoints_mod.logger.setLevel(logging.INFO)
    try:
        yield records
    finally:
        endpoints_mod.logger.removeHandler(handler)
        endpoints_mod.logger.setLevel(prev_level)
        endpoints_mod.logger.disabled = prev_disabled


def _make_activity(
    incident_id: str,
    label: str,
    target: int,
    *,
    include_fusion: bool = True,
    use_target_id_only: bool = False,
) -> SimpleNamespace:
    details = {
        "label": label,
        "target": target,
    }
    if not use_target_id_only:
        details["source_incident_id"] = incident_id
    if include_fusion:
        details["fusion_features"] = {
            "s_user": 0.2,
            "s_endpoint": 0.1,
            "s_network_flow": 0.8 if target == 1 else 0.1,
            "s_network_graph": 0.3,
            "s_open_set_distance": 0.1,
            "stage_count": 0.2,
        }
    return SimpleNamespace(target_id=incident_id, details=details)


def test_keeps_only_latest_feedback_per_incident(capture_endpoint_logs):
    activities = [
        _make_activity("inc-1", "CONFIRMED", 1),
        _make_activity("inc-1", "FALSE_POSITIVE", 0),
        _make_activity("inc-1", "CONFIRMED", 1),
        _make_activity("inc-2", "FALSE_POSITIVE", 0),
    ]
    samples = _build_fusion_feedback_samples(activities)

    assert len(samples) == 2
    by_id = {s["source_incident_id"]: s for s in samples}
    assert by_id["inc-1"]["label"] == "CONFIRMED"
    assert by_id["inc-1"]["target"] == 1
    assert by_id["inc-2"]["label"] == "FALSE_POSITIVE"
    assert by_id["inc-2"]["target"] == 0

    assert any(
        "raw_rows=4" in msg
        and "deduplicated_rows=2" in msg
        and "'CONFIRMED': 1" in msg
        and "'FALSE_POSITIVE': 1" in msg
        for msg in capture_endpoint_logs
    )


def test_overwrites_earlier_label_with_later_label_per_incident(capture_endpoint_logs):
    activities = [
        _make_activity("inc-10", "CONFIRMED", 1),
        _make_activity("inc-10", "FALSE_POSITIVE", 0),
    ]
    samples = _build_fusion_feedback_samples(activities)

    assert len(samples) == 1
    assert samples[0]["label"] == "FALSE_POSITIVE"
    assert samples[0]["target"] == 0
    assert any(
        "raw_rows=2" in msg
        and "deduplicated_rows=1" in msg
        and "'FALSE_POSITIVE': 1" in msg
        for msg in capture_endpoint_logs
    )


def test_filters_non_fusion_and_falls_back_to_target_id(capture_endpoint_logs):
    activities = [
        _make_activity("inc-a", "CONFIRMED", 1, include_fusion=False),
        _make_activity("inc-b", "CONFIRMED", 1, use_target_id_only=True),
        _make_activity("inc-b", "FALSE_POSITIVE", 0, use_target_id_only=True),
    ]
    samples = _build_fusion_feedback_samples(activities)

    assert len(samples) == 1
    assert samples[0]["label"] == "FALSE_POSITIVE"
    assert any("raw_rows=2" in msg and "deduplicated_rows=1" in msg for msg in capture_endpoint_logs)
