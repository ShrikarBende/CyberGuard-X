import logging
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ml.datasets.adapters import CSECICIDS2018Adapter, UNSWNB15Adapter, normalize_cse_label
from ml.evaluation.cross_dataset import (
    _prepare_pair, cross_dataset_evaluation, cse_capture_day_evaluation,
)


def _fixture_capture(path: Path, labels):
    pd.DataFrame({
        "Dst Port": [80 + i for i in range(len(labels))],
        "Flow Duration": [10 + i for i in range(len(labels))],
        "Tot Fwd Pkts": [2] * len(labels),
        "TotLen Fwd Pkts": [20] * len(labels),
        "Flow IAT Mean": [2.0] * len(labels),
        "Flow IAT Std": [1.0] * len(labels),
        "Label": labels,
    }).to_csv(path, index=False)


def test_cse_adapter_maps_fixture_schema_labels_and_capture_provenance(tmp_path):
    path = tmp_path / "Wednesday-14-02-2018.csv"
    _fixture_capture(path, ["BENIGN", "DoS attacks-Hulk", "Infilteration"])
    frame = CSECICIDS2018Adapter(root=tmp_path).load_capture(path)
    assert frame["Label"].tolist() == ["BENIGN", "DosDDoS", "Infiltration"]
    assert frame["raw_label"].tolist() == ["BENIGN", "DoS attacks-Hulk", "Infilteration"]
    assert frame["_capture_day"].tolist() == ["2018-02-14"] * 3
    assert frame["Destination Port"].tolist() == [80, 81, 82]
    assert np.isfinite(frame["Flow Duration"]).all()


@pytest.mark.parametrize("raw,expected", [
    ("BENIGN", "BENIGN"), ("FTP-BruteForce", "BruteForce"),
    ("SSH-Bruteforce", "BruteForce"), ("Brute Force -Web", "WebAttack"),
    ("Brute Force -XSS", "WebAttack"), ("DDoS attacks-HOIC", "DosDDoS"),
    ("PortScan", "PortScan"), ("Infilteration", "Infiltration"),
])
def test_cse_label_mapping_is_explicit(raw, expected):
    assert normalize_cse_label(raw) == expected


def test_unsupported_or_ambiguous_cse_labels_fail_closed():
    with pytest.raises(ValueError, match="Unsupported CSE"):
        normalize_cse_label("DDoS and PortScan")


def test_cse_adapter_missing_data_error_is_actionable(tmp_path):
    with pytest.raises(FileNotFoundError, match="Place the processed per-day CSV"):
        CSECICIDS2018Adapter(root=tmp_path / "missing").capture_files()


def test_cse_adapter_rejects_bad_numeric_features(tmp_path):
    path = tmp_path / "2018-02-14.csv"
    _fixture_capture(path, ["BENIGN"])
    frame = pd.read_csv(path)
    frame["Flow Duration"] = frame["Flow Duration"].astype(object)
    frame.loc[0, "Flow Duration"] = "not numeric"
    frame.to_csv(path, index=False)
    with pytest.raises(ValueError, match="non-numeric values"):
        CSECICIDS2018Adapter(root=tmp_path).load_capture(path)


def test_cse_adapter_drops_nonfinite_rate_rows_and_logs_exact_count(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    path = tmp_path / "Wednesday-14-02-2018.csv"
    _fixture_capture(path, ["BENIGN", "Bot", "BENIGN", "Bot", "BENIGN", "Bot", "BENIGN"])
    frame = pd.read_csv(path)
    frame["Flow Byts/s"] = [1.0, np.inf, 2.0, 3.0, 4.0, -np.inf, 6.0]
    frame["Flow Pkts/s"] = [1.0, 1.0, -np.inf, 4.0, 5.0, 6.0, 7.0]
    frame.to_csv(path, index=False)

    result = CSECICIDS2018Adapter(root=tmp_path, read_chunk_rows=2).load_capture(path)

    assert len(result) == 4
    assert result["Label"].tolist() == ["BENIGN", "Bot", "BENIGN", "BENIGN"]
    assert result.attrs["cse_ingestion"]["dropped_nonfinite_rows"] == 3
    assert result.attrs["cse_ingestion"]["source_rows"] == 7
    assert result["Flow Bytes/s"].dtype == np.float32
    assert result["Flow Packets/s"].dtype == np.float32
    assert np.isfinite(result[["Flow Bytes/s", "Flow Packets/s"]].to_numpy()).all()
    assert "dropped exactly 3 rows" in caplog.text


def test_cse_adapter_sampling_is_deterministic_and_retains_all_attacks(tmp_path):
    path = tmp_path / "2018-02-14.csv"
    _fixture_capture(path, ["BENIGN"] * 20 + ["Bot"] * 3)
    adapter = CSECICIDS2018Adapter(root=tmp_path, max_rows_per_capture=10, sampling_seed=7, read_chunk_rows=4)

    first = adapter.load_capture(path)
    second = adapter.load_capture(path)

    assert first.equals(second)
    assert len(first) == 13
    assert (first["Label"] == "Bot").sum() == 3
    assert (first["Label"] == "BENIGN").sum() == 10
    assert first["Flow Duration"].dtype == np.float32
    assert first.attrs["cse_ingestion"]["benign_rows_sampled_out"] == 10


def test_cross_dataset_pair_reports_only_shared_labels_and_features():
    train = pd.DataFrame({"Flow Duration": [1, 2, 3], "Flow IAT Mean": [1, 2, 3],
                          "Flow IAT Std": [1, 1, 1], "Total Length of Fwd Packets": [10, 20, 30],
                          "Total Length of Bwd Packets": [2, 4, 6], "Destination Port": [80, 81, 82],
                          "Label": ["BENIGN", "Bot", "Infiltration"]})
    test = pd.DataFrame({"Flow Duration": [4, 5], "Flow IAT Mean": [2, 2], "Flow IAT Std": [1, 1],
                         "Total Length of Fwd Packets": [40, 50], "Total Length of Bwd Packets": [8, 10],
                         "Destination Port": [83, 84], "Label": ["BENIGN", "Bot"]})
    x_train, y_train, x_test, y_test, features, classes, excluded = _prepare_pair(train, test)
    assert classes == ["BENIGN", "Bot"]
    assert x_train.shape[1] == x_test.shape[1] == len(features)
    assert excluded["train_labels"] == ["Infiltration"]
    assert len(y_train) == 2 and len(y_test) == 2


def test_cse_multicapture_requires_multiple_named_days(tmp_path):
    _fixture_capture(tmp_path / "2018-02-14.csv", ["BENIGN", "Bot"])
    with pytest.raises(ValueError, match="at least two date-identifiable"):
        cse_capture_day_evaluation(CSECICIDS2018Adapter(root=tmp_path))


def _majority_model(x_train, y_train, _x_val, _y_val, _classes, _seed):
    prediction = int(np.bincount(y_train).argmax())

    class Model:
        def predict(self, values):
            return np.full(len(values), prediction, dtype=np.int64)

    return Model()


def _canonical_fixture(labels):
    return pd.DataFrame({
        "Flow Duration": np.arange(len(labels), dtype=float) + 1,
        "Flow IAT Mean": np.ones(len(labels)), "Flow IAT Std": np.ones(len(labels)),
        "Total Length of Fwd Packets": np.arange(len(labels), dtype=float) + 10,
        "Total Length of Bwd Packets": np.arange(len(labels), dtype=float) + 2,
        "Destination Port": np.full(len(labels), 443), "Label": labels,
    })


def test_cross_dataset_evaluation_runs_both_transfer_directions():
    labels = ["BENIGN"] * 10 + ["Bot"] * 10
    result = cross_dataset_evaluation(
        _canonical_fixture(labels), _canonical_fixture(labels),
        model_factory=_majority_model,
    )
    assert result["protocol"].startswith("cross-dataset")
    assert set(result["directions"]) == {
        "CICIDS2017_to_CSE-CIC-IDS2018", "CSE-CIC-IDS2018_to_CICIDS2017",
    }
    assert all(row["test_rows"] == 20 for row in result["directions"].values())


def test_cse_leave_one_capture_day_out_keeps_each_day_held_out(tmp_path):
    labels = ["BENIGN"] * 8 + ["Bot"] * 8
    _fixture_capture(tmp_path / "2018-02-14.csv", labels)
    _fixture_capture(tmp_path / "2018-02-15.csv", labels)
    result = cse_capture_day_evaluation(
        CSECICIDS2018Adapter(root=tmp_path), model_factory=_majority_model,
    )
    assert result["n_capture_days"] == 2
    assert result["protocol"].startswith("CSE-CIC-IDS2018 binary attack-vs-benign")
    assert [fold["held_out_capture_day"] for fold in result["folds"]] == ["2018-02-14", "2018-02-15"]
    assert all(fold["test_rows"] == 16 for fold in result["folds"])
    assert result["family_capture_counts"]["Bot"] == {
        "capture_days": ["2018-02-14", "2018-02-15"],
        "n_capture_days": 2, "n_files": 2, "flow_count": 16,
    }
    assert result["aggregate"]["per_family_recall"]["Bot"]["n_capture_days_with_test_support"] == 2


def test_cse_binary_capture_day_evaluation_supports_families_on_unique_days(tmp_path):
    _fixture_capture(tmp_path / "2018-02-14.csv", ["BENIGN"] * 8 + ["Bot"] * 3)
    _fixture_capture(tmp_path / "2018-02-22.csv", ["BENIGN"] * 8 + ["Brute Force -Web"] * 3)
    result = cse_capture_day_evaluation(
        CSECICIDS2018Adapter(root=tmp_path), model_factory=_majority_model,
    )
    assert len(result["folds"]) == 2
    assert result["aggregate"]["per_family_recall"]["Bot"]["support"] == 3
    assert result["aggregate"]["per_family_recall"]["WebAttack"]["support"] == 3
    assert [fold["n_capture_days"] if "n_capture_days" in fold else fold["held_out_capture_day"]
            for fold in result["folds"]] == ["2018-02-14", "2018-02-22"]


def test_unsw_adapter_is_optional_and_reports_its_local_files(tmp_path):
    adapter = UNSWNB15Adapter(root=tmp_path)
    assert adapter.capture_files() == []
