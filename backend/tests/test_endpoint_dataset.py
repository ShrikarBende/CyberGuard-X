import json

import numpy as np
import pandas as pd
import pytest

from ml.endpoint_branch import FEATURE_NAMES
from ml.endpoint_dataset import load_labeled_sysmon_windows


def _window(label="benign", capture_id="capture-a"):
    return {**{name: 0 for name in FEATURE_NAMES}, "label": label, "capture_id": capture_id}


def test_labeled_sysmon_csv_requires_explicit_labels_and_capture_groups(tmp_path):
    path = tmp_path / "windows.csv"
    pd.DataFrame([_window("benign"), _window("attack", "capture-b")]).to_csv(path, index=False)
    x, y, groups = load_labeled_sysmon_windows(path)
    assert x.shape == (2, len(FEATURE_NAMES))
    assert np.isfinite(x).all()
    assert y.tolist() == [0, 1]
    assert groups == ["capture-a", "capture-b"]


def test_labeled_sysmon_jsonl_supports_nested_features(tmp_path):
    path = tmp_path / "windows.jsonl"
    records = [{"features": {name: 1 for name in FEATURE_NAMES}, "label": "attack", "capture_id": "vm-1"}]
    path.write_text("\n".join(json.dumps(row) for row in records), encoding="utf-8")
    x, y, groups = load_labeled_sysmon_windows(path)
    assert x.tolist() == [[1.0] * len(FEATURE_NAMES)]
    assert y.tolist() == [1]
    assert groups == ["vm-1"]


@pytest.mark.parametrize("record,fragment", [
    ({"label": "attack", "capture_id": "c"}, "missing feature columns"),
    ({**{name: 0 for name in FEATURE_NAMES}, "capture_id": "c"}, "explicit label"),
    ({**{name: 0 for name in FEATURE_NAMES}, "label": "unknown", "capture_id": "c"}, "label must be"),
    ({**{name: 0 for name in FEATURE_NAMES}, "label": "benign"}, "capture_id is required"),
    ({**{name: -1 for name in FEATURE_NAMES}, "label": "benign", "capture_id": "c"}, "non-negative"),
    ({**{name: "NaN" for name in FEATURE_NAMES}, "label": "benign", "capture_id": "c"}, "finite"),
])
def test_labeled_sysmon_jsonl_rejects_unverifiable_windows(tmp_path, record, fragment):
    path = tmp_path / "invalid.jsonl"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match=fragment):
        load_labeled_sysmon_windows(path)


def test_labeled_sysmon_loader_rejects_bad_json_and_unknown_extensions(tmp_path):
    bad_json = tmp_path / "bad.jsonl"
    bad_json.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSONL"):
        load_labeled_sysmon_windows(bad_json)
    unsupported = tmp_path / "windows.json"
    unsupported.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a .csv"):
        load_labeled_sysmon_windows(unsupported)
