"""Train and bundle the benign-only endpoint behavioral anomaly branch."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import torch
from torch import nn
from sklearn.ensemble import IsolationForest

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
from ml.endpoint_branch import (DenoisingAutoencoder, FEATURE_NAMES, generate_synthetic_endpoint_data,
                                load_sysmon_feature_rows)

ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "endpoint_behavior.bundle.pkl"


def train_endpoint_branch(benign_features: np.ndarray | None = None, output_path: Path | None = None,
                          epochs: int = 80, seed: int = 42,
                          sysmon_dir: Path | None = None) -> Path:
    """Fit from local Sysmon captures when present; otherwise use synthetic baseline."""
    torch.manual_seed(seed)
    training_source = "provided_benign_baseline"
    if benign_features is None:
        source_dir = Path(sysmon_dir) if sysmon_dir else BACKEND_DIR / "datasets" / "sysmon"
        has_sysmon_files = source_dir.is_dir() and any(
            any(source_dir.rglob(pattern)) for pattern in ("*.json", "*.jsonl", "*.zip")
        )
        if has_sysmon_files:
            benign_features = load_sysmon_feature_rows(source_dir)
            training_source = "real_sysmon_captures_unsupervised"
        else:
            data, labels = generate_synthetic_endpoint_data(1200, seed)
            benign_features = data[labels == 0]
            training_source = "synthetic_fallback"
    raw = np.asarray(benign_features, dtype=np.float32)
    min_rows = 2 if training_source == "real_sysmon_captures_unsupervised" else 20
    if raw.ndim != 2 or raw.shape[1] != len(FEATURE_NAMES) or len(raw) < min_rows:
        raise ValueError(f"training features must have at least {min_rows} rows and {len(FEATURE_NAMES)} columns")
    if not np.isfinite(raw).all() or (raw < 0).any():
        raise ValueError("benign training features must be finite and non-negative")
    # Bounds and both estimators see benign training rows exclusively.
    lower = np.quantile(raw, .01, axis=0).astype(np.float32)
    upper = np.quantile(raw, .99, axis=0).astype(np.float32)
    span = np.maximum(upper - lower, 1e-6).astype(np.float32)
    scaled = np.clip((raw - lower) / span, 0, 1)
    model = DenoisingAutoencoder(len(FEATURE_NAMES))
    optimizer = torch.optim.Adam(model.parameters(), lr=.005)
    train_tensor = torch.tensor(scaled, dtype=torch.float32)
    model.train()
    for _ in range(epochs):
        noise = train_tensor + torch.randn_like(train_tensor) * .08
        mask = torch.rand_like(train_tensor) < .05
        noise = torch.where(mask, torch.zeros_like(noise), noise).clamp(0, 1)
        optimizer.zero_grad()
        loss = nn.functional.mse_loss(model(noise), train_tensor)
        loss.backward()
        optimizer.step()
    model.eval()
    with torch.no_grad():
        reconstructed = model(train_tensor).numpy()
    recon = np.square(scaled - reconstructed).mean(axis=1)
    forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1)
    forest.fit(scaled)
    forest_values = -forest.score_samples(scaled)
    recon_bounds = np.quantile(recon, [.50, .99]).astype(float)
    forest_bounds = np.quantile(forest_values, [.50, .99]).astype(float)
    destination = Path(output_path) if output_path else ARTIFACT_PATH
    bundle = {"dae": model, "isolation_forest": forest, "feature_names": FEATURE_NAMES,
        "feature_min": lower, "feature_range": span,
        "reconstruction_bounds": recon_bounds, "reconstruction_span": max(float(recon_bounds[1]-recon_bounds[0]), 1e-8),
        "iforest_bounds": forest_bounds, "iforest_span": max(float(forest_bounds[1]-forest_bounds[0]), 1e-8),
        "score_weights": (.6, .4), "model_version": "endpoint-dae-iforest-v1", "seed": seed,
        "training_rows": len(raw), "training_date": datetime.now(timezone.utc).isoformat(),
        "training_scope": "benign_baseline_only" if training_source == "provided_benign_baseline" else training_source,
        "training_source": training_source}
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, destination, compress=3)
    return destination


if __name__ == "__main__":
    path = train_endpoint_branch()
    print(f"Endpoint artifact: {path}")
