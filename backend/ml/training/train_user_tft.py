"""Train the compact Temporal Fusion Transformer user-sequence branch."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from torch.utils.data import DataLoader, TensorDataset

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
from ml.sequence_graph import (USER_FEATURE_NAMES, TemporalFusionTransformer,
                              generate_synthetic_user_sequences, load_user_sequences)
from app.core.config import settings
from ml.artifact_security import save_model_bundle

ARTIFACT_PATH = BACKEND_DIR / "saved_models" / "user_tft.bundle.pkl"
SEQUENCE_LENGTH = 24


def _score_quantiles(values: np.ndarray) -> dict[str, float]:
    quantiles = np.quantile(np.asarray(values, dtype=float), [0, .5, .95, 1])
    return {key: float(value) for key, value in zip(("min", "median", "p95", "max"), quantiles)}


def _attention_targets(sequences: np.ndarray, valid_mask: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Assign weak attention targets to event steps carrying risk indicators."""
    risk_by_step = sequences[:, :, [1, 3, 4, 5, 6]].sum(axis=-1).astype(np.float32)
    risk_by_step *= valid_mask
    targets = np.zeros_like(risk_by_step, dtype=np.float32)
    risk_bearing = risk_by_step.sum(axis=1) > 0
    for i in range(len(targets)):
        weights = risk_by_step[i] if risk_bearing[i] else valid_mask[i].astype(np.float32)
        total = float(weights.sum())
        if total > 0:
            targets[i] = weights / total
    return targets, risk_bearing


def train_user_tft(dataset_dir: Path | None = None, output_path: Path | None = None,
                   epochs: int = 8, seed: int = 42) -> Path:
    torch.manual_seed(seed)
    root = Path(dataset_dir) if dataset_dir else BACKEND_DIR / "datasets"
    sysmon_dir = root / "sysmon" if (root / "sysmon").exists() else root
    cert_dir = root / "cert" if (root / "cert").exists() else None
    has_real_files = (sysmon_dir.is_dir() and any(any(sysmon_dir.rglob(p)) for p in ("*.json", "*.jsonl"))) or (
        cert_dir is not None and cert_dir.is_dir() and any(cert_dir.rglob("logon.csv"))
    )
    if has_real_files:
        sequences, labels, groups = load_user_sequences(sysmon_dir, cert_dir, SEQUENCE_LENGTH, return_groups=True)
        if len(sequences) < 2:
            raise ValueError("User sequence files were found, but did not contain enough parseable user events")
        source = "real_sysmon_cert_weak_labels"
    else:
        sequences, labels = generate_synthetic_user_sequences(512, seed, SEQUENCE_LENGTH)
        groups = np.asarray([f"synthetic-user-{i // 8}" for i in range(len(labels))], dtype=str)
        source = "synthetic_fallback"

    indexes = np.arange(len(labels))
    if len(groups) != len(indexes):
        raise ValueError("one user/host group identifier is required per sequence")
    train_indexes, val_indexes = next(GroupShuffleSplit(n_splits=1, test_size=.2, random_state=seed)
                                     .split(indexes, labels, groups=groups))
    if not set(groups[train_indexes]).isdisjoint(set(groups[val_indexes])):
        raise AssertionError("user/host group leaked across TFT train and validation")
    # Fit normalization on training sequences only.
    flattened = sequences[train_indexes].reshape(-1, sequences.shape[-1])
    lower = np.quantile(flattened, .01, axis=0).astype(np.float32)
    upper = np.quantile(flattened, .99, axis=0).astype(np.float32)
    span = np.maximum(upper - lower, 1e-6).astype(np.float32)
    scaled = np.clip((sequences - lower) / span, 0, 1)
    # The raw host-count feature is >= 1 for real steps and 0 for padding.
    valid_mask = np.any(sequences != 0, axis=-1)
    attention_targets, risk_bearing = _attention_targets(sequences, valid_mask)
    train_x = torch.as_tensor(scaled[train_indexes], dtype=torch.float32)
    train_y = torch.as_tensor(labels[train_indexes], dtype=torch.float32)
    train_mask = torch.as_tensor(valid_mask[train_indexes], dtype=torch.bool)
    train_attention_target = torch.as_tensor(attention_targets[train_indexes], dtype=torch.float32)
    loader = DataLoader(
        TensorDataset(train_x, train_y, train_mask, train_attention_target), batch_size=64, shuffle=True,
        generator=torch.Generator().manual_seed(seed),
    )
    val_x = torch.as_tensor(scaled[val_indexes], dtype=torch.float32)
    val_y = labels[val_indexes].astype(int)
    val_mask = torch.as_tensor(valid_mask[val_indexes], dtype=torch.bool)

    model = TemporalFusionTransformer(len(USER_FEATURE_NAMES), hidden_dim=32, heads=4)
    optimizer = torch.optim.Adam(model.parameters(), lr=.001, weight_decay=1e-4)
    positives = max(1.0, float(train_y.sum()))
    negatives = max(1.0, float(len(train_y)) - positives)
    positive_weight = min(negatives / positives, 20.0)
    pos_weight = torch.tensor([positive_weight])
    model.train()
    for _ in range(epochs):
        for batch_x, batch_y, batch_mask, batch_attention_target in loader:
            optimizer.zero_grad()
            logits, attention, _ = model(batch_x, batch_mask)
            classification_loss = F.binary_cross_entropy_with_logits(logits, batch_y, pos_weight=pos_weight)
            last_step_attention = attention[:, -1, :]
            attention_loss = -(batch_attention_target * torch.log(last_step_attention + 1e-8)).sum(dim=1).mean()
            loss = classification_loss + .5 * attention_loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

    model.eval()
    with torch.no_grad():
        val_logits, val_attention, val_variables = model(val_x, val_mask)
        train_logits, _, _ = model(train_x, train_mask)
        val_scores = torch.sigmoid(val_logits).cpu().numpy()
        train_scores = torch.sigmoid(train_logits).cpu().numpy()
        val_attention = val_attention[:, -1, :].cpu().numpy()
        val_variables = val_variables[:, -1, :].cpu().numpy()
    predictions = (val_scores >= .5).astype(int)
    attention_entropies, attention_uniform = [], []
    risk_attention_uniform = []
    for row_index, (attention_row, valid_row) in enumerate(zip(val_attention, valid_mask[val_indexes])):
        weights = attention_row[valid_row]
        if len(weights) > 1:
            weights = np.clip(weights, 1e-12, 1.0)
            weights = weights / weights.sum()
            attention_entropies.append(float(-(weights * np.log(weights)).sum() / np.log(len(weights))))
            uniform = bool(np.allclose(weights, 1 / len(weights), atol=.01))
            attention_uniform.append(uniform)
            if risk_bearing[val_indexes[row_index]]:
                risk_attention_uniform.append(uniform)
    validation_metrics = {
        "accuracy_at_0_5": float(accuracy_score(val_y, predictions)),
        "positive_precision_at_0_5": float(precision_score(val_y, predictions, zero_division=0)),
        "positive_recall_at_0_5": float(recall_score(val_y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(val_y, val_scores)) if len(np.unique(val_y)) > 1 else None,
        "positive_fraction": float(val_y.mean()),
        "predicted_positive_fraction": float(predictions.mean()),
        "score_quantiles": _score_quantiles(val_scores),
        "temporal_attention_normalized_entropy_mean": float(np.mean(attention_entropies)) if attention_entropies else None,
        "temporal_attention_uniform_fraction": float(np.mean(attention_uniform)) if attention_uniform else None,
        "risk_bearing_attention_uniform_fraction": float(np.mean(risk_attention_uniform)) if risk_attention_uniform else None,
        "attention_supervision_weight": .5,
        "variable_selection_mean": {name: float(value) for name, value in zip(USER_FEATURE_NAMES, val_variables.mean(axis=0))},
    }

    destination = Path(output_path) if output_path else ARTIFACT_PATH
    bundle = {
        "model": model, "feature_names": USER_FEATURE_NAMES,
        "feature_min": lower, "feature_range": span, "sequence_length": SEQUENCE_LENGTH,
        "model_version": "user-tft-v1", "training_source": source,
        "training_rows": int(len(train_indexes)), "validation_rows": int(len(val_indexes)),
        "positive_rows": int(labels[train_indexes].sum()),
        "validation_positive_rows": int(val_y.sum()),
        "validation_metrics": validation_metrics,
        "train_score_quantiles": _score_quantiles(train_scores),
        "class_weight": {"positive_weight": positive_weight,
                         "negative_count": int(negatives), "positive_count": int(positives)},
        "validation_split": "user_group_disjoint_GroupShuffleSplit_80_20",
        "training_user_groups": int(len(set(groups[train_indexes]))),
        "validation_user_groups": int(len(set(groups[val_indexes]))),
        "attention_supervision": "risk-indicator-weighted event-step targets; zero-signal sessions use uniform over valid steps",
        "label_note": "heuristic risk labels from logon failures, host transitions, privilege elevation, and command activity; not verified account-takeover ground truth",
        "validation_label_provenance": "proxy_weak_labels" if source != "synthetic_fallback" else "synthetic_proxy_weak_labels",
        "seed": seed, "training_date": datetime.now(timezone.utc).isoformat(),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    save_model_bundle(bundle, destination, settings.MODEL_ARTIFACT_HMAC_KEY,
                      registry_name="user_tft" if output_path is None else None)
    return destination


if __name__ == "__main__":
    print(f"User TFT artifact: {train_user_tft()}")
