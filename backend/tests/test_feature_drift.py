import numpy as np
import pandas as pd

from app.detection.engine import score_batch
from ml.feature_drift import monitor_feature_drift


def test_psi_and_ks_alert_on_synthetic_feature_shift():
    rng = np.random.default_rng(410)
    reference = rng.normal(0.0, 1.0, size=(400, 2))
    shifted = rng.normal(2.5, 1.0, size=(300, 2))
    result = monitor_feature_drift(reference, shifted, ["bytes", "duration"], psi_threshold=0.2)
    assert result["alert"] is True
    assert result["features"]["bytes"]["psi"] >= 0.2
    assert result["features"]["bytes"]["ks_statistic"] > 0.5
    assert result["features"]["bytes"]["ks_pvalue"] < 0.05


def test_batch_scoring_surfaces_feature_drift_when_reference_exists():
    class IdentityScaler:
        def transform(self, values):
            return values

    class FixedModel:
        def predict(self, values, raw_score=False):
            return np.tile(np.asarray([[0.0, 1.0]]), (len(values), 1))

        def predict_proba(self, values):
            return np.tile(np.asarray([[0.2, 0.8]]), (len(values), 1))

    rng = np.random.default_rng(12)
    reference = rng.normal(0, 1, size=(100, 2)).astype(np.float32)
    bundle = {
        "feature_names": ["feature_a", "feature_b"], "class_names": ["BENIGN", "Bot"],
        "log1p_columns": [False, False], "scaler": IdentityScaler(), "model": FixedModel(),
        "tau": 0.1,
        "drift_reference": {"feature_names": ["feature_a", "feature_b"], "values": reference},
    }
    incoming = pd.DataFrame({"feature_a": np.full(6, 5.0), "feature_b": np.full(6, 0.0)})
    result = score_batch(incoming, bundle)
    assert result[0]["feature_drift"]["alert"] is True
    assert result[0]["feature_drift"]["features"]["feature_a"]["ks_pvalue"] < 0.05
