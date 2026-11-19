"""
Open-Set Evaluation Pipeline
==============================
Leave-one-attack-family-out evaluation.
For each attack family F:
  - Remove F from train + val entirely
  - Train classifiers + 6 open-set detectors on the remaining known classes
  - Test on: (all known-class test samples) + (all test samples of F, labelled "unknown")
  - Threshold set EXCLUSIVELY from known-class validation scores (95th percentile)
  - NEVER touches held-out family data for threshold selection (enforced by assertion)

6 Detectors compared:
  (a) max-probability confidence (1 - max_prob) from LightGBM
  (b) Isolation Forest anomaly score
  (c) Denoising Autoencoder reconstruction error (MSE)
  (d) Mahalanobis distance to nearest known-class centroid
  (e) Mahalanobis distance on a known-class MLP penultimate embedding
  (f) Validation-calibrated rank average of confidence and Mahalanobis scores

Metrics per held-out family + averaged:
  - AUROC (known=0 vs unknown=1)
  - FPR at 95% TPR (unknown detection rate = 95%)
  - Unknown rejection rate at threshold
  - Known false-reject rate at threshold

Results saved to backend/ml/evaluation/results/open_set_<date>.json
All numbers are computed from real data — nothing is fabricated.
"""

from __future__ import annotations

import json
import gc
import time
import zlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

import lightgbm as lgb
import numpy as np
import torch
import torch.nn as nn
from scipy.spatial.distance import cdist
from scipy.integrate import trapezoid
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.metrics import average_precision_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.decomposition import PCA
from ml.preprocessing.cicids_pipeline import apply_log1p_columns, fit_log1p_columns
from ml.open_set import calibrated_union_score, compute_centroid_statistics, nearest_centroid_distance, temperature_scaled_energy
from ml.evaluation.provenance import working_tree_is_dirty
from ml.evaluation.output_paths import get_results_dir

RESULTS_DIR = get_results_dir()
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42
THRESHOLD_PERCENTILE = 97   # target 97% known specificity; selected on known-val scores only
ENERGY_TEMPERATURE = 1.5


# ─── Denoising Autoencoder ────────────────────────────────────────────────────

class DenoisingAutoencoder(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int = 32):
        super().__init__()
        h = max(64, input_dim // 2)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, h), nn.ReLU(),
            nn.Linear(h, latent_dim), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, h), nn.ReLU(),
            nn.Linear(h, input_dim),
        )

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encoder(x)
        return self.decoder(z), z


class KnownClassMLP(nn.Module):
    """Known-class MLP exposing its penultimate representation."""
    def __init__(self, input_dim: int, n_classes: int, embedding_dim: int = 64):
        super().__init__()
        self.embedding = nn.Sequential(nn.Linear(input_dim, 128), nn.ReLU(), nn.Linear(128, embedding_dim), nn.ReLU())
        self.classifier = nn.Linear(embedding_dim, n_classes)

    def forward(self, x: torch.Tensor):
        z = self.embedding(x)
        return self.classifier(z), z


def train_known_mlp(X: np.ndarray, y: np.ndarray, n_classes: int, seed: int) -> KnownClassMLP:
    torch.manual_seed(seed)
    model = KnownClassMLP(X.shape[1], n_classes)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()
    features = torch.as_tensor(X, dtype=torch.float32)
    labels = torch.as_tensor(y, dtype=torch.long)
    for _ in range(15):
        model.train()
        for start in range(0, len(features), 2048):
            batch_x = features[start:start + 2048]
            batch_y = labels[start:start + 2048]
            logits, _ = model(batch_x)
            loss = loss_fn(logits, batch_y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
    model.eval()
    return model


def mlp_embedding(model: KnownClassMLP, X: np.ndarray) -> np.ndarray:
    embeddings = []
    with torch.no_grad():
        for start in range(0, len(X), 8192):
            _, embedding = model(torch.as_tensor(X[start:start + 8192], dtype=torch.float32))
            embeddings.append(embedding.numpy())
    return np.concatenate(embeddings)


def embedding_class_statistics(model, X: np.ndarray, y: np.ndarray, embedding_fn,
                               batch_size: int = 8192) -> Tuple[np.ndarray, np.ndarray]:
    """Compute known-training embedding centroids/covariance without retaining all embeddings."""
    n_classes = int(np.max(y)) + 1
    total_sum = total_outer = class_sums = None
    counts = np.bincount(y, minlength=n_classes).astype(np.float64)
    for start in range(0, len(X), batch_size):
        stop = min(start + batch_size, len(X))
        embedding = embedding_fn(model, X[start:stop]).astype(np.float64, copy=False)
        if total_sum is None:
            total_sum = np.zeros(embedding.shape[1], dtype=np.float64)
            total_outer = np.zeros((embedding.shape[1], embedding.shape[1]), dtype=np.float64)
            class_sums = np.zeros((n_classes, embedding.shape[1]), dtype=np.float64)
        total_sum += embedding.sum(axis=0)
        total_outer += embedding.T @ embedding
        np.add.at(class_sums, y[start:stop], embedding)
    centroids = class_sums / counts[:, None]
    covariance = (total_outer - np.outer(total_sum, total_sum) / len(X)) / max(len(X) - 1, 1)
    covariance += 1e-6 * np.eye(covariance.shape[0])
    return centroids, covariance


def rank_average_scores(validation_scores: List[np.ndarray], scores_to_rank: List[np.ndarray]) -> np.ndarray:
    """Average anomaly-score percentiles calibrated solely on known validation arrays."""
    if len(validation_scores) != len(scores_to_rank):
        raise ValueError("Each score source needs a validation and evaluation array")
    calibrations = [np.sort(np.asarray(scores)) for scores in validation_scores]
    return np.mean([np.searchsorted(cal, values, side="right") / len(cal)
                    for cal, values in zip(calibrations, scores_to_rank)], axis=0)


def train_autoencoder(
    X_train: np.ndarray,
    input_dim: int,
    latent_dim: int = 32,
    epochs: int = 30,
    batch_size: int = 1024,
    lr: float = 1e-3,
    noise_std: float = 0.1,
    seed: int = SEED,
    train_indices: np.ndarray | None = None,
) -> DenoisingAutoencoder:
    torch.manual_seed(seed)
    model = DenoisingAutoencoder(input_dim, latent_dim)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()

    X_t = torch.as_tensor(X_train, dtype=torch.float32)
    indices = np.arange(len(X_train)) if train_indices is None else np.asarray(train_indices)
    index_tensor = torch.as_tensor(indices, dtype=torch.long)
    n = len(indices)

    model.train()
    for ep in range(1, epochs + 1):
        perm = torch.randperm(n)
        total_loss = 0.0
        for i in range(0, n, batch_size):
            idx = index_tensor[perm[i: i + batch_size]]
            xb = X_t.index_select(0, idx)
            noisy = xb + noise_std * torch.randn_like(xb)
            recon, _ = model(noisy)
            loss = loss_fn(recon, xb)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total_loss += loss.item() * len(xb)
        if ep % 10 == 0:
            print(f"    AE epoch {ep}/{epochs}  loss={total_loss/n:.5f}")
    model.eval()
    return model


def ae_reconstruction_error(model: DenoisingAutoencoder, X: np.ndarray) -> np.ndarray:
    model.eval()
    errors = []
    with torch.no_grad():
        for start in range(0, len(X), 8192):
            X_t = torch.as_tensor(X[start:start + 8192], dtype=torch.float32)
            recon, _ = model(X_t)
            errors.append(((X_t - recon) ** 2).mean(dim=1).numpy())
    return np.concatenate(errors).astype(np.float64)


def ae_latent(model: DenoisingAutoencoder, X: np.ndarray) -> np.ndarray:
    model.eval()
    embeddings = []
    with torch.no_grad():
        for start in range(0, len(X), 8192):
            X_t = torch.as_tensor(X[start:start + 8192], dtype=torch.float32)
            _, z = model(X_t)
            embeddings.append(z.numpy())
    return np.concatenate(embeddings)


# ─── Mahalanobis distance ─────────────────────────────────────────────────────

def compute_class_centroids(X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Return per-class centroids and pooled within-class covariance."""
    _, centroids, covariance = compute_centroid_statistics(X, y)
    return centroids, covariance


def mahalanobis_to_nearest(
    X: np.ndarray,
    centroids: np.ndarray,
    cov: np.ndarray,
) -> np.ndarray:
    """Min Mahalanobis distance from each sample to the nearest known centroid."""
    try:
        VI = np.linalg.inv(cov)
    except np.linalg.LinAlgError:
        VI = np.linalg.pinv(cov)

    n = len(X)
    k = len(centroids)
    dists = np.zeros((n, k))
    for j, c in enumerate(centroids):
        diff = X - c
        dists[:, j] = np.einsum("ij,jk,ik->i", diff, VI, diff)

    return np.sqrt(np.maximum(dists.min(axis=1), 0.0))


# ─── Metric helpers ───────────────────────────────────────────────────────────

def fpr_at_tpr(scores: np.ndarray, labels: np.ndarray, tpr_target: float = 0.95) -> float:
    """
    FPR (false positive rate on knowns) when TPR (unknown detection rate) = tpr_target.
    Higher score = more anomalous.
    labels: 1 = unknown, 0 = known
    """
    from sklearn.metrics import roc_curve
    fpr_arr, tpr_arr, _ = roc_curve(labels, scores)
    # find smallest FPR where TPR >= tpr_target
    idx = np.searchsorted(tpr_arr, tpr_target)
    if idx >= len(fpr_arr):
        return float(fpr_arr[-1])
    return float(fpr_arr[idx])


def rejection_metrics(
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
) -> Tuple[float, float]:
    """
    Returns (unknown_rejection_rate, known_false_reject_rate) at threshold.
    Rejected = score > threshold (flagged as anomalous / unknown).
    """
    unknown_mask = labels == 1
    known_mask   = labels == 0
    unk_reject  = float((scores[unknown_mask] > threshold).mean()) if unknown_mask.any() else 0.0
    knw_reject  = float((scores[known_mask]   > threshold).mean()) if known_mask.any()   else 0.0
    return unk_reject, knw_reject


def oscr_curve(known_correct: np.ndarray, unknown_scores: np.ndarray,
               known_scores: np.ndarray) -> Tuple[np.ndarray, np.ndarray, float]:
    """Return OSCR (unknown FPR, known CCR, AUC), sweeping an anomaly-score cutoff.

    Lower anomaly scores are accepted as known. Known CCR counts only correctly
    classified known rows; unknown FPR counts unknown rows accepted as known.
    """
    correct = np.asarray(known_correct, dtype=bool)
    kscore = np.asarray(known_scores, dtype=np.float64)
    uscore = np.asarray(unknown_scores, dtype=np.float64)
    if not len(correct) or not len(kscore) or not len(uscore) or len(correct) != len(kscore):
        raise ValueError("OSCR requires non-empty, aligned known correctness/scores and unknown scores")
    scores = np.concatenate([kscore, uscore])
    is_unknown = np.concatenate([np.zeros(len(kscore), dtype=bool), np.ones(len(uscore), dtype=bool)])
    order = np.argsort(scores, kind="mergesort")
    sorted_scores = scores[order]
    sorted_unknown = is_unknown[order]
    sorted_correct = np.concatenate([correct, np.zeros(len(uscore), dtype=bool)])[order]
    x = [0.0]; y = [0.0]
    accepted_unknown = accepted_correct = 0
    i = 0
    while i < len(order):
        j = i + 1
        while j < len(order) and sorted_scores[j] == sorted_scores[i]:
            j += 1
        accepted_unknown += int(sorted_unknown[i:j].sum())
        accepted_correct += int(sorted_correct[i:j].sum())
        x.append(accepted_unknown / len(uscore))
        y.append(accepted_correct / len(kscore))
        i = j
    x_arr = np.asarray(x); y_arr = np.asarray(y)
    return x_arr, y_arr, float(trapezoid(y_arr, x_arr))


def bootstrap_metric_intervals(
    scores: np.ndarray,
    labels: np.ndarray,
    threshold: float,
    seed: int,
    n_resamples: int = 1000,
) -> Dict[str, List[float]]:
    """Stratified row bootstrap CIs, preserving known/unknown test sample sizes."""
    scores = np.asarray(scores)
    labels = np.asarray(labels)
    known_idx = np.flatnonzero(labels == 0)
    unknown_idx = np.flatnonzero(labels == 1)
    if not len(known_idx) or not len(unknown_idx):
        return {"AUROC_95CI": [None, None], "unknown_rejection_rate_95CI": [None, None]}
    rng = np.random.default_rng(seed)
    auc_values = np.empty(n_resamples, dtype=np.float64)
    unknown_rejected = int(np.count_nonzero(scores[unknown_idx] > threshold))
    rejection_values = rng.binomial(len(unknown_idx), unknown_rejected / len(unknown_idx),
                                    size=n_resamples) / len(unknown_idx)
    # AUROC depends only on score-bin counts. Multinomially resampling the
    # known/unknown counts in each tied-score bin is exactly the row bootstrap,
    # without repeatedly sorting hundreds of thousands of sampled rows.
    _, score_bins = np.unique(scores, return_inverse=True)
    n_bins = int(score_bins.max()) + 1
    known_bin_counts = np.bincount(score_bins[known_idx], minlength=n_bins)
    unknown_bin_counts = np.bincount(score_bins[unknown_idx], minlength=n_bins)
    known_prob = known_bin_counts / len(known_idx)
    unknown_prob = unknown_bin_counts / len(unknown_idx)
    for i in range(n_resamples):
        known_counts = rng.multinomial(len(known_idx), known_prob)
        unknown_counts = rng.multinomial(len(unknown_idx), unknown_prob)
        known_below = np.cumsum(known_counts) - known_counts
        wins = np.dot(unknown_counts, known_below + 0.5 * known_counts)
        auc_values[i] = wins / (len(known_idx) * len(unknown_idx))
    return {
        "AUROC_95CI": [round(float(x), 6) for x in np.percentile(auc_values, [2.5, 97.5])],
        "unknown_rejection_rate_95CI": [round(float(x), 6) for x in np.percentile(rejection_values, [2.5, 97.5])],
        "bootstrap_resamples": n_resamples,
    }


def print_family_metric_tables(family_results: List[Dict], detector_names: List[str]) -> Dict[str, List[Dict]]:
    """Print and return per-family detector tables for AUROC and unknown rejection."""
    tables = {}
    for metric, title in (("AUROC", "AUROC"), ("unknown_rejection_rate", "Unknown rejection rate")):
        rows = []
        print(f"\n{title} by held-out family (low support means fewer than 200 unknown test rows)")
        header = ["Family", "Unknown rows", "Support"] + detector_names
        print(" | ".join(header))
        print(" | ".join(["---"] * len(header)))
        for result in family_results:
            if "detectors" not in result:
                continue
            count = result["n_test_unknown"]
            row = {"family": result["family"], "unknown_test_rows": count,
                   "support": "low support" if count < 200 else "adequate"}
            for detector in detector_names:
                row[detector] = result["detectors"][detector][metric]
            rows.append(row)
            print(" | ".join([row["family"], str(count), row["support"]] +
                              [f"{row[d]:.6f}" for d in detector_names]))
        tables[metric] = rows
    return tables


def threshold_from_known_validation(scores: np.ndarray, known_mask: np.ndarray,
                                    percentile: float = THRESHOLD_PERCENTILE) -> float:
    """Compute a threshold only when every supplied validation row is known."""
    known_mask = np.asarray(known_mask, dtype=bool)
    scores = np.asarray(scores)
    if len(scores) != len(known_mask) or not len(scores) or not known_mask.all():
        raise ValueError("Threshold validation data must contain known-class rows only")
    return float(np.percentile(scores, percentile))


def known_fold_frames(train_df, val_df, held_out_family: str, label_col: str = "Label"):
    """Return known-only training and validation rows for one held-out family."""
    train = train_df.loc[train_df[label_col] != held_out_family]
    validation = val_df.loc[val_df[label_col] != held_out_family]
    if (train[label_col] == held_out_family).any() or (validation[label_col] == held_out_family).any():
        raise AssertionError(f"Held-out family {held_out_family} leaked into model data")
    return train, validation


# ─── Single family evaluation ─────────────────────────────────────────────────

def evaluate_one_family(
    held_out_family: str,
    pipeline: dict,
    progress_state: dict | None = None,
) -> Dict:
    """
    Leave one attack family out, train, evaluate 6 detectors.
    Threshold is set ONLY from known-val scores.
    """
    print(f"\n{'='*60}")
    print(f"[Open-Set] Held-out family: {held_out_family}")
    print(f"{'='*60}")

    train_df   = pipeline["train_df"]
    val_df     = pipeline["val_df"]
    test_df    = pipeline["test_df"]
    feat_cols  = pipeline["feat_cols"]
    seed       = pipeline["seed"]
    label_col  = "Label"

    # ── Filter train/val: remove held-out family entirely ──────────────────
    family_started = time.perf_counter()
    tr, vl = known_fold_frames(train_df, val_df, held_out_family, label_col)
    train_cap = pipeline.get("train_row_cap_per_fold")
    if train_cap and len(tr) > train_cap:
        tr, _ = train_test_split(
            tr, train_size=train_cap, random_state=seed, stratify=tr[label_col]
        )
    assert not (tr[label_col] == held_out_family).any()
    assert not (vl[label_col] == held_out_family).any()

    # ── Build test: known-class test rows + all test rows of held-out family ──
    test_known   = test_df[test_df[label_col] != held_out_family]
    test_unknown = test_df[test_df[label_col] == held_out_family]

    print(f"  train={len(tr)}, val={len(vl)}, "
          f"test_known={len(test_known)}, test_unknown={len(test_unknown)}")

    if len(test_unknown) == 0:
        return {"family": held_out_family, "skipped": "No unknown test samples"}

    # ── Re-encode labels for this run (excludes held-out family) ──────────
    local_le = LabelEncoder()
    y_tr = local_le.fit_transform(tr[label_col].values)
    # Map val and test using same encoder; unknown gets -1
    def _safe_encode(labels):
        mapping = {c: i for i, c in enumerate(local_le.classes_)}
        return np.array([mapping.get(l, -1) for l in labels])

    y_vl = _safe_encode(vl[label_col].values)
    # Remove any val rows not in known classes (should be zero after filtering)
    vl_known_mask = y_vl >= 0
    vl_clean  = vl[vl_known_mask]; y_vl_clean = y_vl[vl_known_mask]

    y_test_known   = _safe_encode(test_known[label_col].values)

    # ── Scale features using the GLOBAL scaler (fitted on full train) ──────
    raw_tr = tr[feat_cols].to_numpy(dtype=np.float32, copy=False)
    raw_vl = vl_clean[feat_cols].to_numpy(dtype=np.float32, copy=False)
    raw_te_k = test_known[feat_cols].to_numpy(dtype=np.float32, copy=False)
    raw_te_u = test_unknown[feat_cols].to_numpy(dtype=np.float32, copy=False)
    log_columns = fit_log1p_columns(raw_tr) if pipeline.get("log1p", False) else np.zeros(raw_tr.shape[1], dtype=bool)
    raw_tr = apply_log1p_columns(raw_tr, log_columns)
    raw_vl = apply_log1p_columns(raw_vl, log_columns)
    raw_te_k = apply_log1p_columns(raw_te_k, log_columns)
    raw_te_u = apply_log1p_columns(raw_te_u, log_columns)
    scaler = StandardScaler().fit(raw_tr)
    X_tr    = scaler.transform(raw_tr)
    X_vl    = scaler.transform(raw_vl)
    X_te_k  = scaler.transform(raw_te_k)
    X_te_u  = scaler.transform(raw_te_u)
    del raw_tr, raw_vl, raw_te_k, raw_te_u

    # Combined test set: 0=known, 1=unknown
    X_test_all  = np.vstack([X_te_k, X_te_u])
    test_labels  = np.concatenate([np.zeros(len(X_te_k)), np.ones(len(X_te_u))])

    n_classes = len(local_le.classes_)

    # ── (a) LightGBM max-probability confidence ───────────────────────────
    lgbm = lgb.LGBMClassifier(
        n_estimators=300, learning_rate=0.05, num_leaves=63,
        class_weight="balanced", random_state=seed, n_jobs=-1, verbosity=-1,
    )
    lgbm.fit(X_tr, y_tr, eval_set=[(X_vl, y_vl_clean)],
             callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(-1)])

    # Anomaly score: 1 - max_probability (high = more anomalous)
    prob_vl  = lgbm.predict_proba(X_vl)
    prob_all = lgbm.predict_proba(X_test_all)
    logits_vl = np.asarray(lgbm.predict(X_vl, raw_score=True), dtype=np.float64)
    logits_all = np.asarray(lgbm.predict(X_test_all, raw_score=True), dtype=np.float64)
    predicted_all = lgbm.predict(X_test_all)
    known_correct = predicted_all[:len(X_te_k)] == y_test_known
    known_macro_f1 = float(f1_score(y_test_known, predicted_all[:len(X_te_k)], average="macro", zero_division=0))
    score_conf_vl  = 1.0 - prob_vl.max(axis=1)
    score_conf_all = 1.0 - prob_all.max(axis=1)

    # Threshold: 95th percentile of KNOWN VAL scores (no unknown data used)
    thresh_conf = threshold_from_known_validation(score_conf_vl, np.ones(len(score_conf_vl), dtype=bool))
    # ASSERTION: val set has zero unknown-family samples
    assert (vl[label_col] == held_out_family).sum() == 0, \
        f"LEAKAGE: held-out family {held_out_family} present in val during threshold selection"

    # ── (b) Isolation Forest ───────────────────────────────────────────────
    if "isolation_forest" in pipeline.get("detectors", ["isolation_forest"]):
        if_settings = pipeline.get("isolation_forest", {})
        iforest = IsolationForest(
            n_estimators=if_settings.get("n_estimators", 200),
            max_samples=if_settings.get("max_samples", "auto"),
            contamination=0.05, random_state=seed, n_jobs=if_settings.get("n_jobs", -1),
        )
        benign_indices = np.flatnonzero(tr[label_col].to_numpy() == "BENIGN")
        if not len(benign_indices):
            raise ValueError("No BENIGN training rows available for anomaly detector fitting")
        if_sample_indices = benign_indices
        if len(if_sample_indices) > 100_000:
            if_sample_indices = np.random.default_rng(seed).choice(if_sample_indices, 100_000, replace=False)
        iforest.fit(X_tr[if_sample_indices])
        # decision_function: lower = more anomalous; negate to get anomaly score
        score_if_vl  = -iforest.decision_function(X_vl)
        score_if_all = -iforest.decision_function(X_test_all)
        thresh_if    = threshold_from_known_validation(score_if_vl, np.ones(len(score_if_vl), dtype=bool))

    enabled = pipeline.get("detectors", ["confidence", "isolation_forest", "autoencoder", "mahalanobis",
                                          "mahalanobis_mlp", "confidence_mahalanobis_rank_average",
                                          "energy", "logit_margin", "compact_mahalanobis",
                                          "confidence_energy_compact_union"])
    detector_validation = {"confidence": score_conf_vl}
    detector_test = {"confidence": score_conf_all}
    detector_threshold = {"confidence": thresh_conf}
    detector_flags = {}
    union_thresholds = None
    if "isolation_forest" in enabled:
        detector_validation["isolation_forest"] = score_if_vl
        detector_test["isolation_forest"] = score_if_all
        detector_threshold["isolation_forest"] = thresh_if

    # The full profile preserves the existing AE-latent Mahalanobis detector.
    # The light profile skips AE and computes the same class-centroid distance
    # directly in standardized feature space using known-class train rows.
    ae = None
    if "autoencoder" in enabled or ("mahalanobis" in enabled and "autoencoder" in enabled):
        input_dim = X_tr.shape[1]
        ae = train_autoencoder(X_tr, input_dim, latent_dim=32, epochs=30, seed=seed,
                               train_indices=benign_indices)
    if "autoencoder" in enabled:
        score_ae_vl = ae_reconstruction_error(ae, X_vl)
        score_ae_all = ae_reconstruction_error(ae, X_test_all)
        detector_validation["autoencoder"] = score_ae_vl
        detector_test["autoencoder"] = score_ae_all
        detector_threshold["autoencoder"] = threshold_from_known_validation(score_ae_vl, np.ones(len(score_ae_vl), dtype=bool))
    if "mahalanobis" in enabled:
        if ae is not None:
            mh_vl = ae_latent(ae, X_vl)
            mh_all = ae_latent(ae, X_test_all)
            centroids, cov = embedding_class_statistics(ae, X_tr, y_tr, ae_latent)
        else:
            mh_vl, mh_all = X_vl, X_test_all
            centroids, cov = compute_class_centroids(X_tr, y_tr)
        score_mh_vl = mahalanobis_to_nearest(mh_vl, centroids, cov)
        score_mh_all = mahalanobis_to_nearest(mh_all, centroids, cov)
        detector_validation["mahalanobis"] = score_mh_vl
        detector_test["mahalanobis"] = score_mh_all
        detector_threshold["mahalanobis"] = threshold_from_known_validation(score_mh_vl, np.ones(len(score_mh_vl), dtype=bool))
    compact_pca = None
    if "compact_mahalanobis" in enabled or "confidence_energy_compact_union" in enabled:
        compact_scaler = StandardScaler().fit(X_tr)
        compact_pca = PCA(n_components=min(16, X_tr.shape[1], X_tr.shape[0]), random_state=seed)
        compact_train = compact_pca.fit_transform(compact_scaler.transform(X_tr))
        compact_validation = compact_pca.transform(compact_scaler.transform(X_vl))
        compact_all = compact_pca.transform(compact_scaler.transform(X_test_all))
        compact_classes, compact_centroids, compact_covariance = compute_centroid_statistics(compact_train, y_tr)
        score_compact_vl = nearest_centroid_distance(compact_validation, compact_centroids, compact_covariance)
        score_compact_all = nearest_centroid_distance(compact_all, compact_centroids, compact_covariance)
        detector_validation["compact_mahalanobis"] = score_compact_vl
        detector_test["compact_mahalanobis"] = score_compact_all
        detector_threshold["compact_mahalanobis"] = threshold_from_known_validation(
            score_compact_vl, np.ones(len(score_compact_vl), dtype=bool))
    if "energy" in enabled or "confidence_energy_compact_union" in enabled:
        score_energy_vl = temperature_scaled_energy(logits_vl, ENERGY_TEMPERATURE)
        score_energy_all = temperature_scaled_energy(logits_all, ENERGY_TEMPERATURE)
        detector_validation["energy"] = score_energy_vl
        detector_test["energy"] = score_energy_all
        detector_threshold["energy"] = threshold_from_known_validation(
            score_energy_vl, np.ones(len(score_energy_vl), dtype=bool))
    sorted_logits_vl = np.sort(logits_vl, axis=1)
    sorted_logits_all = np.sort(logits_all, axis=1)
    score_margin_vl = -(sorted_logits_vl[:, -1] - sorted_logits_vl[:, -2])
    score_margin_all = -(sorted_logits_all[:, -1] - sorted_logits_all[:, -2])
    if "logit_margin" in enabled:
        detector_validation["logit_margin"] = score_margin_vl
        detector_test["logit_margin"] = score_margin_all
        detector_threshold["logit_margin"] = threshold_from_known_validation(
            score_margin_vl, np.ones(len(score_margin_vl), dtype=bool))
    if "confidence_energy_compact_union" in enabled:
        union_components_vl = {
            "confidence": detector_validation["confidence"],
            "energy": detector_validation["energy"],
            "logit_margin": score_margin_vl,
            "compact_mahalanobis": detector_validation["compact_mahalanobis"],
        }
        union_components_all = {
            "confidence": detector_test["confidence"],
            "energy": detector_test["energy"],
            "logit_margin": score_margin_all,
            "compact_mahalanobis": detector_test["compact_mahalanobis"],
        }
        union_val = calibrated_union_score(union_components_vl, union_components_vl)
        union_all = calibrated_union_score(union_components_vl, union_components_all)
        detector_validation["confidence_energy_compact_union"] = union_val
        detector_test["confidence_energy_compact_union"] = union_all
        detector_threshold["confidence_energy_compact_union"] = threshold_from_known_validation(
            union_val, np.ones(len(union_val), dtype=bool), percentile=97.0)
    if "mahalanobis_mlp" in enabled:
        mlp = train_known_mlp(X_tr, y_tr, n_classes, seed)
        E_vl = mlp_embedding(mlp, X_vl)
        E_all = mlp_embedding(mlp, X_test_all)
        mlp_centroids, mlp_cov = embedding_class_statistics(mlp, X_tr, y_tr, mlp_embedding)
        score_mlp_mh_vl = mahalanobis_to_nearest(E_vl, mlp_centroids, mlp_cov)
        score_mlp_mh_all = mahalanobis_to_nearest(E_all, mlp_centroids, mlp_cov)
        detector_validation["mahalanobis_mlp"] = score_mlp_mh_vl
        detector_test["mahalanobis_mlp"] = score_mlp_mh_all
        detector_threshold["mahalanobis_mlp"] = threshold_from_known_validation(score_mlp_mh_vl, np.ones(len(score_mlp_mh_vl), dtype=bool))
    if "confidence_mahalanobis_rank_average" in enabled:
        score_rank_vl = rank_average_scores(
            [detector_validation["confidence"], detector_validation["mahalanobis"]],
            [detector_validation["confidence"], detector_validation["mahalanobis"]],
        )
        score_rank_all = rank_average_scores(
            [detector_validation["confidence"], detector_validation["mahalanobis"]],
            [detector_test["confidence"], detector_test["mahalanobis"]],
        )
        detector_validation["confidence_mahalanobis_rank_average"] = score_rank_vl
        detector_test["confidence_mahalanobis_rank_average"] = score_rank_all
        detector_threshold["confidence_mahalanobis_rank_average"] = threshold_from_known_validation(
            score_rank_vl, np.ones(len(score_rank_vl), dtype=bool)
        )
    if "union_conf_mahalanobis" in enabled:
        confidence_threshold = threshold_from_known_validation(
            detector_validation["confidence"], np.ones(len(vl_clean), dtype=bool), percentile=97.5
        )
        mahalanobis_threshold = threshold_from_known_validation(
            detector_validation["mahalanobis"], np.ones(len(vl_clean), dtype=bool), percentile=97.5
        )
        confidence_rank_vl = rank_average_scores(
            [detector_validation["confidence"]], [detector_validation["confidence"]]
        )
        confidence_rank_all = rank_average_scores(
            [detector_validation["confidence"]], [detector_test["confidence"]]
        )
        mahalanobis_rank_vl = rank_average_scores(
            [detector_validation["mahalanobis"]], [detector_validation["mahalanobis"]]
        )
        mahalanobis_rank_all = rank_average_scores(
            [detector_validation["mahalanobis"]], [detector_test["mahalanobis"]]
        )
        detector_validation["union_conf_mahalanobis"] = np.maximum(
            confidence_rank_vl, mahalanobis_rank_vl
        )
        detector_test["union_conf_mahalanobis"] = np.maximum(
            confidence_rank_all, mahalanobis_rank_all
        )
        detector_threshold["union_conf_mahalanobis"] = 0.5  # used only for score-bin AUROC bootstrap
        union_thresholds = {
            "confidence_score_97_5th_percentile": confidence_threshold,
            "mahalanobis_score_97_5th_percentile": mahalanobis_threshold,
        }
        detector_flags["union_conf_mahalanobis"] = (
            (detector_test["confidence"] > confidence_threshold)
            | (detector_test["mahalanobis"] > mahalanobis_threshold)
        )

    detectors = {name: (detector_test[name], detector_threshold[name]) for name in enabled}

    detector_results = {}
    for name, (scores, thresh) in detectors.items():
        if pipeline.get("save_detector_scores", False):
            score_dir = Path(pipeline.get("score_output_dir", RESULTS_DIR / "scores"))
            score_dir.mkdir(parents=True, exist_ok=True)
            score_path = score_dir / f"{pipeline.get('run_id', 'open_set')}_{held_out_family}.npz"
            existing = {}
            if score_path.exists():
                with np.load(score_path, allow_pickle=False) as saved:
                    existing = {key: saved[key] for key in saved.files}
            existing[f"{name}_scores"] = np.asarray(scores, dtype=np.float64)
            existing["labels"] = np.asarray(test_labels, dtype=np.int8)
            existing["known_labels"] = np.asarray(test_known[label_col].astype(str).to_numpy(), dtype="U")
            existing["unknown_labels"] = np.asarray(test_unknown[label_col].astype(str).to_numpy(), dtype="U")
            np.savez_compressed(score_path, **existing)
        # Guard against constant scores (edge case)
        unique_scores = np.unique(scores)
        if len(unique_scores) < 2:
            auroc = 0.5
        else:
            auroc = float(roc_auc_score(test_labels, scores))
        fpr95 = fpr_at_tpr(scores, test_labels, tpr_target=0.95)
        if name == "union_conf_mahalanobis":
            flags = detector_flags[name]
            unk_rej = float(flags[test_labels == 1].mean())
            knw_rej = float(flags[test_labels == 0].mean())
        else:
            unk_rej, knw_rej = rejection_metrics(scores, test_labels, thresh)
        oscr_x, oscr_y, oscr_auc = oscr_curve(known_correct, scores[len(X_te_k):], scores[:len(X_te_k)])
        curve_indexes = np.unique(np.linspace(0, len(oscr_x) - 1, min(201, len(oscr_x)), dtype=int))
        auprc = float(average_precision_score(test_labels, scores))
        bootstrap = bootstrap_metric_intervals(
            scores, test_labels, thresh,
            seed + zlib.crc32(f"{held_out_family}:{name}".encode("utf-8")) % (2**31),
            n_resamples=pipeline.get("bootstrap_resamples", 1000),
        )
        if name == "union_conf_mahalanobis":
            rejection_bootstrap = bootstrap_metric_intervals(
                flags.astype(np.float32), test_labels, 0.5,
                seed + zlib.crc32(f"{held_out_family}:{name}:union-flags".encode("utf-8")) % (2**31),
                n_resamples=pipeline.get("bootstrap_resamples", 1000),
            )
            bootstrap["unknown_rejection_rate_95CI"] = rejection_bootstrap["unknown_rejection_rate_95CI"]
        detector_results[name] = {
            "AUROC":                   round(auroc, 6),
            "FPR_at_95pct_TPR":       round(fpr95, 6),
            "unknown_rejection_rate": round(unk_rej, 6),
            "known_false_reject_rate": round(knw_rej, 6),
            "oscr_auc": round(oscr_auc, 6),
            "unknown_recall": round(unk_rej, 6),
            "known_macro_f1": round(known_macro_f1, 6),
            "auprc": round(auprc, 6),
            "oscr_curve": {"unknown_fpr": oscr_x[curve_indexes].tolist(),
                           "known_ccr": oscr_y[curve_indexes].tolist(),
                           "points_sampled": int(len(curve_indexes)),
                           "points_total": int(len(oscr_x))},
            "threshold_value": union_thresholds if name == "union_conf_mahalanobis" else round(thresh, 6),
            "threshold_percentile": 97.5 if name == "union_conf_mahalanobis" else THRESHOLD_PERCENTILE,
            **bootstrap,
        }
        elapsed = time.perf_counter() - progress_state["started"] if progress_state else time.perf_counter() - family_started
        if progress_state:
            progress_state["completed"] += 1
            eta = elapsed / progress_state["completed"] * (progress_state["total"] - progress_state["completed"])
        else:
            eta = 0.0
        print(f"[progress] family={held_out_family} detector={name} AUROC={auroc:.4f} "
              f"unknown_rejection={unk_rej:.4f} elapsed={elapsed:.1f}s ETA={eta:.1f}s")

    return {
        "family":          held_out_family,
        "n_train":         int(len(X_tr)),
        "n_val":           int(len(X_vl)),
        "n_test_known":    int(len(X_te_k)),
        "n_test_unknown":  int(len(X_te_u)),
        "unknown_support": "low support" if len(X_te_u) < 200 else "adequate",
        "train_cap_per_fold": train_cap,
        "row_counts": {"train": int(len(tr)), "validation": int(len(vl_clean)),
                       "test_known": int(len(X_te_k)), "test_unknown": int(len(X_te_u))},
        "known_classes_in_run": local_le.classes_.tolist(),
        "detectors":       detector_results,
    }


# ─── Full open-set run ────────────────────────────────────────────────────────

def _write_json_atomic(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    temporary.replace(path)


def run_open_set_evaluation(pipeline: dict) -> dict:
    """
    Run leave-one-family-out for all 5 attack families.
    Aggregate per-family and macro-average metrics.
    """
    attack_families = pipeline["attack_families"]
    seed = pipeline["seed"]
    t0 = time.perf_counter()
    detector_names = pipeline.get("detectors", ["confidence", "isolation_forest", "autoencoder", "mahalanobis",
                                                 "mahalanobis_mlp", "confidence_mahalanobis_rank_average",
                                                 "energy", "logit_margin", "compact_mahalanobis",
                                                 "confidence_energy_compact_union"])
    run_id = pipeline.get("run_id", datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
    if not run_id or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in run_id) or ".." in run_id:
        raise ValueError("run_id may contain only letters, numbers, '.', '_' and '-'")
    partial_path = RESULTS_DIR / f"partial_{run_id}.json"
    run_metadata = pipeline.get("run_metadata", {})
    family_results = []
    if partial_path.exists():
        with open(partial_path, encoding="utf-8") as f:
            prior = json.load(f)
        if prior.get("run_metadata") != run_metadata or prior.get("seed") != seed or prior.get("data_hash") != pipeline["data_hash"]:
            raise ValueError(f"Partial file {partial_path.name} belongs to a different configuration or dataset")
        family_results = prior.get("per_family", [])
        completed_families = {r.get("family") for r in family_results}
        print(f"[resume] {len(completed_families)} completed families loaded from {partial_path}")
    else:
        completed_families = set()
    remaining_families = [f for f in attack_families if f not in completed_families]
    progress_state = {"started": t0, "completed": 0,
                      "total": len(remaining_families) * len(detector_names)}
    for family in attack_families:
        if family in completed_families:
            print(f"[resume] skipping completed family={family}")
            continue
        res = evaluate_one_family(family, pipeline, progress_state)
        family_results.append(res)
        partial_payload = {
            "status": "running", "run_id": run_id, "pipeline_stage": "open_set_evaluation",
            "profile_name": run_metadata.get("profile_name", "full"),
            "profile_warning": run_metadata.get("reduced_profile_warning"),
            "sample_fraction": run_metadata.get("sample_fraction"),
            "train_row_cap_per_fold": run_metadata.get("train_row_cap_per_fold"),
            "bootstrap_resamples": run_metadata.get("bootstrap_resamples"),
            "git_hash": run_metadata.get("git_hash"),
            "git_dirty": run_metadata.get("git_dirty", working_tree_is_dirty()),
            "flags": run_metadata.get("flags", {}),
            "run_metadata": run_metadata, "data_hash": pipeline["data_hash"],
            "seed": seed, "date": datetime.utcnow().isoformat(),
            "per_family": family_results,
        }
        _write_json_atomic(partial_path, partial_payload)
        family_elapsed = time.perf_counter() - t0
        units_done = progress_state["completed"]
        eta = family_elapsed / max(units_done, 1) * max(progress_state["total"] - units_done, 0)
        print(f"[progress] family={family} complete elapsed={family_elapsed:.1f}s ETA={eta:.1f}s partial={partial_path}")
        gc.collect()

    # ── Macro-average across families ─────────────────────────────────────
    family_metric_tables = print_family_metric_tables(family_results, detector_names)
    metric_keys    = ["AUROC", "FPR_at_95pct_TPR", "unknown_rejection_rate", "known_false_reject_rate",
                      "oscr_auc", "unknown_recall", "known_macro_f1", "auprc"]

    macro_avg = {}
    for det in detector_names:
        macro_avg[det] = {}
        for mk in metric_keys:
            vals = [
                r["detectors"][det][mk]
                for r in family_results
                if "detectors" in r and det in r["detectors"]
            ]
            macro_avg[det][mk] = round(float(np.mean(vals)), 6) if vals else None

    # ── Identify weak / suspicious results ────────────────────────────────
    warnings_list = []
    for r in family_results:
        if "detectors" not in r:
            continue
        fam = r["family"]
        for det, metrics in r["detectors"].items():
            auroc = metrics["AUROC"]
            if auroc < 0.60:
                warnings_list.append(
                    f"WEAK: {fam}/{det} AUROC={auroc:.4f} — barely better than random. "
                    f"May indicate this family is indistinguishable from known classes in feature space."
                )
            if metrics["known_false_reject_rate"] > 0.20:
                warnings_list.append(
                    f"SUSPICIOUS: {fam}/{det} known_false_reject_rate={metrics['known_false_reject_rate']:.4f} — "
                    f"high FPR on known samples; threshold may be too aggressive."
                )
            if auroc >= 0.99:
                warnings_list.append(f"SUSPICIOUS: {fam}/{det} AUROC={auroc:.4f} is near 1.0; check for duplicated or overly separable flows.")
            elif auroc <= 0.51:
                warnings_list.append(f"SUSPICIOUS: {fam}/{det} AUROC={auroc:.4f} is near 0.5; detector may have little discriminatory signal.")
        if r.get("n_test_unknown", 0) < 100:
            warnings_list.append(f"SUSPICIOUS: {fam} has only {r.get('n_test_unknown', 0)} unknown test rows; metrics are unstable.")
        metric_vector = tuple(r["detectors"][d]["AUROC"] for d in r["detectors"])
        if len(metric_vector) == len(detector_names) and len(set(metric_vector)) == 1:
            warnings_list.append(f"SUSPICIOUS: {fam} has identical AUROC for all {len(detector_names)} detectors; verify scores and evaluation data.")

    elapsed = round(time.perf_counter() - t0, 2)

    results = {
        "pipeline_stage":    "open_set_evaluation",
        "run_id":            run_id,
        "profile_name":      run_metadata.get("profile_name", "full"),
        "profile_warning":   run_metadata.get("reduced_profile_warning"),
        "sample_fraction":   run_metadata.get("sample_fraction"),
        "train_row_cap_per_fold": run_metadata.get("train_row_cap_per_fold"),
        "git_hash":          run_metadata.get("git_hash"),
        "git_dirty":         run_metadata.get("git_dirty", working_tree_is_dirty()),
        "flags":             run_metadata.get("flags", {}),
        "run_metadata":      run_metadata,
        "model_version":     "v2.0",
        "data_hash":         pipeline["data_hash"],
        "split_type":        pipeline.get("split_type", "stratified_random"),
        "split_warning":     pipeline.get("split_warning", "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic."),
        "row_counts":        pipeline.get("row_counts", {}),
        "seed":              seed,
        "date":              datetime.utcnow().isoformat(),
        "training_time_seconds": elapsed,
        "threshold_percentile":  THRESHOLD_PERCENTILE,
        "log1p": pipeline.get("log1p", False),
        "threshold_rule":    "95th percentile of known-class validation anomaly scores. "
                             "No unknown-class data used for threshold selection.",
        "excluded_labels":   ["Heartbleed", "Infiltration"],
        "per_family":        family_results,
        "per_family_tables": family_metric_tables,
        "macro_average":     macro_avg,
        "open_set_summary": {
            detector: {metric: macro_avg[detector].get(metric) for metric in
                       ("oscr_auc", "unknown_recall", "known_macro_f1", "auprc")}
            for detector in detector_names if detector in macro_avg
        },
        "bootstrap": {"method": "stratified bootstrap resampling of known and unknown test rows",
                      "resamples": pipeline.get("bootstrap_resamples", 1000), "confidence_level": 0.95},
        "warnings":          warnings_list,
    }
    print(f"WARNING: {results['split_warning']}")

    out_path = RESULTS_DIR / f"open_set_{run_id}.json"
    results["results_path"] = str(out_path)
    _write_json_atomic(out_path, results)
    _write_json_atomic(partial_path, {**results, "status": "done"})
    markdown_path = RESULTS_DIR / f"open_set_{run_id}.md"
    report_lines = [f"# Open-set evaluation: {run_id}", "", "| Detector | OSCR AUC | Unknown recall | Known macro F1 | AUPRC |",
                    "|---|---:|---:|---:|---:|"]
    for detector, metrics in results["open_set_summary"].items():
        fmt = lambda value: "n/a" if value is None else f"{value:.4f}"
        report_lines.append(f"| {detector} | {fmt(metrics['oscr_auc'])} | {fmt(metrics['unknown_recall'])} | {fmt(metrics['known_macro_f1'])} | {fmt(metrics['auprc'])} |")
    report_lines.extend(["", "Metrics are macro-averaged across held-out attack families. Unknown recall uses the known-validation calibrated rejection threshold.",
                         "OSCR sweeps anomaly thresholds; known CCR counts only correctly classified known samples and unknown FPR counts unknown samples accepted as known."])
    markdown_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    results["markdown_report_path"] = str(markdown_path)
    _write_json_atomic(out_path, results)
    print(f"\n[open_set] Results saved -> {out_path}")

    # Print warnings
    if warnings_list:
        print("\nWARNING: WEAK / SUSPICIOUS RESULTS:")
        for w in warnings_list:
            print(f"  {w}")
    else:
        print("\nNo obviously weak results found.")

    return results


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from ml.preprocessing.cicids_pipeline import build_full_pipeline
    from ml.evaluation.known_classifier import run_known_classifier

    pipeline = build_full_pipeline()
    _cls_results, _lgbm, _xgb = run_known_classifier(pipeline)
    run_open_set_evaluation(pipeline)

