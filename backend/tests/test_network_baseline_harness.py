"""Integrity tests for frozen CICIDS holdout and session-disjoint baseline folds."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from ml.evaluation.holdout import (  # noqa: E402
    CICIDS_FILES, HOLDOUT_SOURCE_FILE, create_frozen_manifest, load_and_validate_manifest,
)
from ml.evaluation.network_baseline import (  # noqa: E402
    _seed_bootstrap_ci, build_family_fold, load_development_frame,
)
from ml.evaluation.open_set_pipeline import (  # noqa: E402
    binary_operating_metrics, multiclass_split_metrics,
)


def _source_frame(name: str, label: str) -> pd.DataFrame:
    size = 20
    return pd.DataFrame({
        "Flow Duration": np.arange(size, dtype=np.float32),
        "Flow IAT Std": np.full(size, 2.0, dtype=np.float32),
        "Flow IAT Mean": np.full(size, 4.0, dtype=np.float32),
        "Total Length of Fwd Packets": np.full(size, 8.0, dtype=np.float32),
        "Total Length of Bwd Packets": np.full(size, 4.0, dtype=np.float32),
        "Destination Port": np.full(size, 443, dtype=np.int32),
        "Source IP": [f"10.0.{name[-1]}.{index}" for index in range(size)],
        "Label": [label] * size,
    })


def test_frozen_holdout_manifest_is_creation_only_and_hash_pinned(tmp_path, monkeypatch):
    import ml.evaluation.holdout as holdout

    short_files = [f"day{index}.csv" for index in range(8)]
    monkeypatch.setattr(holdout, "CICIDS_FILES", short_files)
    monkeypatch.setattr(holdout, "HOLDOUT_SOURCE_FILE", short_files[0])
    data = tmp_path / "data" / "trafficlabelling"
    data.mkdir(parents=True)
    for index, filename in enumerate(short_files):
        (data / filename).write_bytes(f"source-session-{index}".encode())
    manifest_path = tmp_path / "holdout_manifest.json"

    manifest = create_frozen_manifest(manifest_path, tmp_path / "data")
    assert manifest["holdout_source_files"] == [short_files[0]]
    assert set(manifest["development_source_files"]).isdisjoint(manifest["holdout_source_files"])
    assert load_and_validate_manifest(manifest_path, tmp_path / "data")["dataset_sha256"] == manifest["dataset_sha256"]
    with pytest.raises(FileExistsError):
        create_frozen_manifest(manifest_path, tmp_path / "data")

    (data / short_files[-1]).write_bytes(b"changed source data")
    with pytest.raises(ValueError, match="differ from the frozen manifest"):
        load_and_validate_manifest(manifest_path, tmp_path / "data")


def test_development_loader_never_parses_frozen_holdout(tmp_path, monkeypatch):
    import ml.evaluation.network_baseline as baseline

    calls = []
    def load(path):
        calls.append(path.name)
        return _source_frame(path.name, "BENIGN")

    monkeypatch.setattr(baseline, "_load_one_csv", load)
    monkeypatch.setattr(baseline, "DATASETS_DIR", tmp_path)
    manifest = {
        "development_source_files": [name for name in CICIDS_FILES if name != HOLDOUT_SOURCE_FILE],
        "holdout_source_files": [HOLDOUT_SOURCE_FILE],
    }
    frame = load_development_frame(manifest, sample=1.0)
    assert len(calls) == len(CICIDS_FILES) - 1
    assert HOLDOUT_SOURCE_FILE not in calls
    assert HOLDOUT_SOURCE_FILE not in set(frame["_source_file"])


def test_family_fold_keeps_source_sessions_pairwise_disjoint_and_unknown_out_of_train():
    rows = []
    for name, label in (
        ("session-a.csv", "BENIGN"), ("session-b.csv", "DosDDoS"),
        ("session-c.csv", "BruteForce"), ("session-port.csv", "PortScan"),
        ("session-web.csv", "WebAttack"), ("session-bot.csv", "Bot"),
    ):
        frame = _source_frame(name, label)
        frame["_source_file"] = name
        rows.append(frame)
    source = pd.concat(rows, ignore_index=True)

    pipeline, split = build_family_fold(source, "PortScan", 42, ["frozen.csv"])
    train = set(pipeline["train_df"]["_source_file"])
    validation = set(pipeline["val_df"]["_source_file"])
    test = set(pipeline["test_df"]["_source_file"])
    assert not (train & validation or train & test or validation & test)
    assert "session-port.csv" in test
    assert "PortScan" not in set(pipeline["train_df"]["Label"])
    assert "PortScan" not in set(pipeline["val_df"]["Label"])
    assert split["test_source_sessions"] == ["session-port.csv"]


def test_binary_operating_metrics_include_replay_false_alert_and_bootstrap_ci():
    scores = np.array([0.1, 0.8, 0.9, 0.7])
    labels = np.array([0, 0, 1, 1])
    benign = np.array([True, False, False, False])
    result = binary_operating_metrics(scores, labels, 0.75, benign, seed=17, n_resamples=200)
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1"] == 0.5
    assert result["fpr"] == 0.5
    assert result["benign_replay_false_alert_rate"] == 0.0
    assert set(result["bootstrap_95CI"]) == {
        "precision", "recall", "f1", "fpr", "benign_replay_false_alert_rate"
    }


def test_multiclass_split_metrics_match_hand_computed_fixture():
    # Confusion matrix (rows=true, columns=predicted): [[1, 1], [0, 2]].
    result = multiclass_split_metrics(
        y_true=[0, 0, 1, 1],
        y_pred=[0, 1, 1, 1],
        probabilities=[[0.9, 0.1], [0.6, 0.4], [0.3, 0.7], [0.2, 0.8]],
        class_names=["A", "B"],
    )

    assert result["per_class"]["A"] == {
        "precision": 1.0, "recall": 0.5, "f1": 0.666667, "auprc": 1.0, "support": 2,
    }
    assert result["per_class"]["B"] == {
        "precision": 0.666667, "recall": 1.0, "f1": 0.8, "auprc": 1.0, "support": 2,
    }
    assert result["macro_precision"] == 0.833333
    assert result["macro_recall"] == 0.75
    assert result["macro_f1"] == 0.733333
    assert result["macro_auprc"] == 1.0
    assert result["cohen_kappa"] == 0.5
    assert result["mcc"] == 0.57735


def test_multiclass_split_metrics_marks_absent_class_auprc_undefined():
    result = multiclass_split_metrics(
        y_true=[0, 0], y_pred=[0, 0], probabilities=[[0.8, 0.2], [0.7, 0.3]],
        class_names=["present", "absent"],
    )
    assert result["per_class"]["absent"]["precision"] == 0.0
    assert result["per_class"]["absent"]["recall"] == 0.0
    assert result["per_class"]["absent"]["f1"] == 0.0
    assert result["per_class"]["absent"]["auprc"] is None
    assert result["macro_auprc"] == 1.0


def test_multiclass_split_metrics_rejects_incompatible_probability_shape():
    with pytest.raises(ValueError, match="incompatible shapes"):
        multiclass_split_metrics([0], [0], [[1.0]], ["A", "B"])


def test_seed_bootstrap_interval_is_repeatable_and_contains_seed_mean():
    values = [0.2, 0.4, 0.6, 0.8, 1.0]
    first = _seed_bootstrap_ci(values, seed=1234)
    assert first == _seed_bootstrap_ci(values, seed=1234)
    assert first[0] <= np.mean(values) <= first[1]
