"""Coverage for replay sample metadata across both CICIDS CSV layouts."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from ml.training.make_replay_sample import (  # noqa: E402
    NETWORK_METADATA_COLUMNS,
    _add_replay_metadata,
    _feature_columns,
)


def test_85_column_layout_preserves_metadata_and_excludes_it_from_features():
    metadata = {
        "Flow ID": ["source-flow"],
        "Source IP": ["192.0.2.10"],
        "Source Port": [12345],
        "Destination IP": ["192.0.2.20"],
        "Protocol": [6],
        "Timestamp": ["2017-07-03 08:00:00"],
    }
    frame = pd.DataFrame({**metadata, "Destination Port": [443], "Flow Duration": [12], "_source_file": ["Monday-WorkingHours.pcap_ISCX.csv"]})

    enriched = _add_replay_metadata(frame)

    for name, values in metadata.items():
        assert enriched[name].tolist() == values
    features = _feature_columns([*metadata, "Destination Port", "Flow Duration"])
    assert features == ["Destination Port", "Flow Duration"]
    assert not set(features) & NETWORK_METADATA_COLUMNS


def test_79_column_layout_gets_deterministic_sequential_metadata_without_label_input():
    frame = pd.DataFrame({
        "Destination Port": [80, 443, 22],
        "Flow Duration": [1, 2, 3],
        "_source_file": ["Monday-WorkingHours.pcap_ISCX.csv"] * 3,
    }, index=[8, 4, 9])

    first = _add_replay_metadata(frame)
    second = _add_replay_metadata(frame)

    metadata = ["Timestamp", "Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol"]
    pd.testing.assert_frame_equal(first[metadata], second[metadata])
    timestamps = pd.to_datetime(first["Timestamp"])
    assert timestamps.diff().dropna().dt.total_seconds().tolist() == [1.0, 1.0]
    assert first["Timestamp"].iloc[0] == "2017-07-03 08:00:00"
    assert first["Flow ID"].is_unique
    assert first["Source IP"].str.startswith("198.18.").all()
    assert first["Destination IP"].str.startswith("198.19.").all()
    assert first["Source Port"].between(1024, 65535).all()
    assert first["Protocol"].between(0, 255).all()
    assert not set(_feature_columns([*metadata, "Destination Port", "Flow Duration"])) & set(metadata)


def test_79_column_layout_fills_every_file_group_when_metadata_columns_are_absent():
    frame = pd.DataFrame({
        "Destination Port": [80, 443],
        "Flow Duration": [1, 2],
        "_source_file": [
            "Monday-WorkingHours.pcap_ISCX.csv",
            "Tuesday-WorkingHours.pcap_ISCX.csv",
        ],
    })

    enriched = _add_replay_metadata(frame)

    metadata = ["Timestamp", "Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol"]
    assert enriched[metadata].notna().all().all()
    assert enriched["Timestamp"].tolist() == ["2017-07-03 08:00:00", "2017-07-04 08:00:00"]

