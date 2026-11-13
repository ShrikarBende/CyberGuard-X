"""
CICIDS2017 Data Pipeline
========================
- Loads all 8 official CICIDS2017 CSVs
- Cleans: strip column whitespace, replace inf/NaN, drop exact duplicates
- Maps raw labels -> attack families; excludes Heartbleed & Infiltration (too rare)
- Splits per-file: 70% train | 10% val | 20% test  (stratified, no Timestamp present)
- Fits StandardScaler on TRAIN split only; transforms val and test
- Caches cleaned DataFrames as Parquet for fast reloads
- Never fabricates or hardcodes any numbers

LABEL FAMILIES
  BENIGN       -> BENIGN
  DosDDoS      -> DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest, DDoS
  PortScan     -> PortScan
  BruteForce   -> FTP-Patator, SSH-Patator
  WebAttack    -> Web Attack * Brute Force / XSS / Sql Injection
  Bot          -> Bot
  EXCLUDED     -> Heartbleed, Infiltration
"""

from __future__ import annotations

import hashlib
import os
import warnings
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent.parent          # backend/
DATASETS_DIR = ROOT / "datasets"
CACHE_DIR = DATASETS_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ─── All 8 CICIDS2017 files ───────────────────────────────────────────────────
CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# ─── Label mapping ────────────────────────────────────────────────────────────
# Unicode hyphen variants appear in the web-attack labels
_WEB_ATTACK_VARIANTS = {
    "Web Attack \u00e2\u0080\u0093 Brute Force",   # â€" (Windows-1252 artifact)
    "Web Attack \u2013 Brute Force",               # –
    "Web Attack – Brute Force",
    "Web Attack - Brute Force",
    "Web Attack \u00e2\u0080\u0093 XSS",
    "Web Attack \u2013 XSS",
    "Web Attack – XSS",
    "Web Attack - XSS",
    "Web Attack \u00e2\u0080\u0093 Sql Injection",
    "Web Attack \u2013 Sql Injection",
    "Web Attack – Sql Injection",
    "Web Attack - Sql Injection",
}

LABEL_MAP: Dict[str, str] = {}
# Benign
LABEL_MAP["BENIGN"] = "BENIGN"
# DoS / DDoS family
for lbl in ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "DDoS"]:
    LABEL_MAP[lbl] = "DosDDoS"
# PortScan
LABEL_MAP["PortScan"] = "PortScan"
# BruteForce
LABEL_MAP["FTP-Patator"] = "BruteForce"
LABEL_MAP["SSH-Patator"] = "BruteForce"
# WebAttack (all variants)
for v in _WEB_ATTACK_VARIANTS:
    LABEL_MAP[v] = "WebAttack"
# Bot
LABEL_MAP["Bot"] = "Bot"
# Excluded (too rare – not added to LABEL_MAP intentionally)
EXCLUDED_LABELS = {"Heartbleed", "Infiltration"}

KNOWN_FAMILIES = ["BENIGN", "DosDDoS", "PortScan", "BruteForce", "WebAttack", "Bot"]
ATTACK_FAMILIES = ["DosDDoS", "PortScan", "BruteForce", "WebAttack", "Bot"]

# ─── Numeric feature columns (all CICIDS2017 numeric cols minus Label) ────────
# We load all 78 numeric cols; Label is handled separately
LABEL_COL = "Label"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _file_md5(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            blk = f.read(chunk)
            if not blk:
                break
            h.update(blk)
    return h.hexdigest()


def _parquet_cache_path(csv_path: Path) -> Path:
    return CACHE_DIR / (csv_path.stem + ".clean-v2.parquet")


def _load_one_csv(csv_path: Path, force_reload: bool = False) -> pd.DataFrame:
    """
    Load, clean, and cache one CICIDS2017 CSV as Parquet.
    - Strip column-name whitespace
    - Replace inf / -inf with NaN, drop NaN rows
    - Drop exact duplicate rows
    - Map labels; drop excluded & unmapped labels
    """
    cache_path = _parquet_cache_path(csv_path)

    if not force_reload and cache_path.exists():
        print(f"  [cache hit] Loading {cache_path.name}")
        return pd.read_parquet(cache_path)

    print(f"  [csv read ] Reading {csv_path.name} ...")
    df = pd.read_csv(csv_path, low_memory=False)

    # 1. Strip column whitespace
    df.columns = df.columns.str.strip()

    # 2. Replace inf/-inf with NaN, drop NaN rows
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before_nan = len(df)
    df.dropna(inplace=True)
    print(f"    NaN drop : {before_nan} -> {len(df)}")

    # 3. Drop exact duplicate rows
    before_dup = len(df)
    df.drop_duplicates(inplace=True)
    print(f"    Dedup    : {before_dup} -> {len(df)}")

    # 4. Map labels; handle unicode hyphen variants
    raw_col = df[LABEL_COL].astype(str).str.strip()
    mapped = raw_col.map(LABEL_MAP)
    web_mask = raw_col.str.startswith("Web Attack ")
    mapped.loc[web_mask & raw_col.str.endswith("Brute Force")] = "WebAttack"
    mapped.loc[web_mask & raw_col.str.endswith("XSS")] = "WebAttack"
    mapped.loc[web_mask & raw_col.str.endswith("Sql Injection")] = "WebAttack"
    df[LABEL_COL] = mapped

    # 5. Drop excluded and unmapped rows
    n_before = len(df)
    df.dropna(subset=[LABEL_COL], inplace=True)
    n_after = len(df)
    if n_before != n_after:
        print(f"    Label drop (excluded/unmapped): {n_before} -> {n_after}")

    # 6. Downcast numerics to float32 to reduce memory
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].astype(np.float32)

    # 7. Cache as Parquet
    df.to_parquet(cache_path, index=False)
    print(f"    Cached -> {cache_path.name}")
    return df


def load_all_cicids(force_reload: bool = False) -> pd.DataFrame:
    """
    Assert all 8 CSVs exist, load + clean each, return concatenated DataFrame.
    If any file is missing, raises FileNotFoundError and stops.
    """
    missing = [f for f in CICIDS_FILES if not (DATASETS_DIR / f).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing CICIDS2017 files in {DATASETS_DIR}:\n" + "\n".join(missing)
        )

    combined = None
    for fname in CICIDS_FILES:
        csv_path = DATASETS_DIR / fname
        df = _load_one_csv(csv_path, force_reload=force_reload)
        df["_source_file"] = fname   # keep provenance
        combined = df if combined is None else pd.concat([combined, df], axis=0, ignore_index=True)
        del df
    combined, exact_dropped, conflicts_dropped = deduplicate_flows(combined)
    print(f"Deduplication: exact duplicate rows dropped={exact_dropped:,}; "
          f"conflicting-label feature rows dropped={conflicts_dropped:,}")
    print(f"\nTotal rows after cleaning: {len(combined):,}")
    print("Label distribution:")
    print(combined[LABEL_COL].value_counts().to_string())
    return combined


def deduplicate_flows(df: pd.DataFrame) -> Tuple[pd.DataFrame, int, int]:
    """Drop exact duplicates, then all feature-identical groups with label conflicts."""
    feature_cols = [c for c in df.columns if c not in {LABEL_COL, "_source_file"}]
    feature_parts, exact_parts = [], []
    for start in range(0, len(df), 100_000):
        block = df.iloc[start:start + 100_000]
        feature_parts.append(pd.util.hash_pandas_object(block[feature_cols], index=False))
        exact_parts.append(pd.util.hash_pandas_object(block[feature_cols + [LABEL_COL]], index=False))
    feature_hash = pd.concat(feature_parts, ignore_index=True)
    exact_hash = pd.concat(exact_parts, ignore_index=True)
    exact_mask = ~exact_hash.duplicated(keep="first")
    exact = df.loc[exact_mask]
    unique_feature_hash = feature_hash.loc[exact_mask]
    exact_dropped = len(df) - len(exact)
    labels_per_flow = pd.DataFrame({"flow": unique_feature_hash.to_numpy(), "label": exact[LABEL_COL].to_numpy()})
    conflict_hashes = labels_per_flow.groupby("flow", sort=False)["label"].nunique()
    conflicts = set(conflict_hashes[conflict_hashes > 1].index)
    conflict_index = unique_feature_hash.isin(conflicts).to_numpy()
    conflicts_dropped = int(conflict_index.sum())
    return exact.loc[~conflict_index].reset_index(drop=True), exact_dropped, conflicts_dropped


def build_splits(
    df: pd.DataFrame,
    seed: int = 42,
    val_ratio: float = 0.10,
    test_ratio: float = 0.20,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Per-file stratified split: 70% train | 10% val | 20% test.
    Scaler is NOT fitted here — that's done in get_feature_matrices().
    No Timestamp column exists in CICIDS2017; we use stratified split and warn.
    """
    warning = "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic."
    print(f"WARNING: {warning}")
    warnings.warn(
        warning,
        UserWarning,
        stacklevel=2,
    )

    train_frames, val_frames, test_frames = [], [], []

    for source_file, group in df.groupby("_source_file"):
        labels = group[LABEL_COL]
        # First split off test
        try:
            X_tv, X_test = train_test_split(
                group, test_size=test_ratio, stratify=labels, random_state=seed
            )
            # Then split val from train+val
            val_size_adj = val_ratio / (1.0 - test_ratio)
            X_train, X_val = train_test_split(
                X_tv, test_size=val_size_adj, stratify=X_tv[LABEL_COL], random_state=seed
            )
        except ValueError:
            # Fallback if stratification fails (e.g., single-class file)
            n = len(group)
            cut_test = int(n * (1 - test_ratio))
            cut_val = int(cut_test * (1 - val_ratio / (1 - test_ratio)))
            X_train = group.iloc[:cut_val]
            X_val = group.iloc[cut_val:cut_test]
            X_test = group.iloc[cut_test:]

        train_frames.append(X_train)
        val_frames.append(X_val)
        test_frames.append(X_test)
        print(
            f"  {source_file}: train={len(X_train)}, val={len(X_val)}, test={len(X_test)}"
        )

    train_df = pd.concat(train_frames, ignore_index=True)
    val_df = pd.concat(val_frames, ignore_index=True)
    test_df = pd.concat(test_frames, ignore_index=True)
    return train_df, val_df, test_df


def _get_feature_cols(df: pd.DataFrame) -> List[str]:
    """Return all numeric feature columns (exclude Label and provenance cols)."""
    exclude = {LABEL_COL, "_source_file"}
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in num_cols if c not in exclude]


def fit_log1p_columns(X_train: np.ndarray) -> np.ndarray:
    """Select non-negative feature columns using training data only."""
    return np.nanmin(X_train, axis=0) >= 0


def apply_log1p_columns(X: np.ndarray, columns: np.ndarray) -> np.ndarray:
    """Apply log1p to selected non-negative values, preserving any negatives."""
    result = np.asarray(X, dtype=np.float32).copy()
    selected = np.flatnonzero(columns)
    if selected.size:
        values = result[:, selected]
        nonnegative = values >= 0
        values[nonnegative] = np.log1p(values[nonnegative])
        result[:, selected] = values
    return result


def get_feature_matrices(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    log1p: bool = False,
) -> Tuple[
    np.ndarray, np.ndarray,       # X_train, y_train
    np.ndarray, np.ndarray,       # X_val,   y_val
    np.ndarray, np.ndarray,       # X_test,  y_test
    List[str],                    # feature_names
    StandardScaler,               # scaler (fitted on train only)
    LabelEncoder,                 # label encoder (fitted on train only)
    List[str],                    # class_names (ordered by encoder)
]:
    """
    Extract numpy feature matrices and encode labels.
    SCALER AND ENCODER ARE FITTED ON TRAIN SPLIT ONLY.
    """
    feat_cols = _get_feature_cols(train_df)

    X_train_raw = train_df[feat_cols].values.astype(np.float32)
    X_val_raw   = val_df[feat_cols].values.astype(np.float32)
    X_test_raw  = test_df[feat_cols].values.astype(np.float32)

    log1p_columns = fit_log1p_columns(X_train_raw) if log1p else np.zeros(X_train_raw.shape[1], dtype=bool)
    X_train_raw = apply_log1p_columns(X_train_raw, log1p_columns)
    X_val_raw = apply_log1p_columns(X_val_raw, log1p_columns)
    X_test_raw = apply_log1p_columns(X_test_raw, log1p_columns)

    # Fit scaler on train only
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val   = scaler.transform(X_val_raw)
    X_test  = scaler.transform(X_test_raw)

    # Fit label encoder on train only
    le = LabelEncoder()
    y_train = le.fit_transform(train_df[LABEL_COL].values)
    y_val   = le.transform(val_df[LABEL_COL].values)
    y_test  = le.transform(test_df[LABEL_COL].values)

    class_names = le.classes_.tolist()
    print(f"\nFeature matrix shapes: train={X_train.shape}, val={X_val.shape}, test={X_test.shape}")
    print(f"Classes (encoder order): {class_names}")

    return X_train, y_train, X_val, y_val, X_test, y_test, feat_cols, scaler, le, class_names


def get_data_hash(df: pd.DataFrame) -> str:
    """Reproducible hash of the cleaned combined DataFrame for result provenance."""
    return hashlib.md5(pd.util.hash_pandas_object(df, index=False).values.tobytes()).hexdigest()[:12]


# ─── Convenience: full pipeline in one call ────────────────────────────────────

def build_full_pipeline(
    force_reload: bool = False,
    seed: int = 42,
    sample: float = 1.0,
    log1p: bool = False,
) -> dict:
    """
    Load, clean, split, scale — returns a dict with everything downstream needs.
    """
    df = load_all_cicids(force_reload=force_reload)
    if not 0 < sample <= 1:
        raise ValueError("sample must be in (0, 1]")
    if sample < 1:
        sampled, _ = train_test_split(df, train_size=sample, random_state=seed, stratify=df[LABEL_COL])
        df = sampled.reset_index(drop=True)
    data_hash = get_data_hash(df)

    train_df, val_df, test_df = build_splits(df, seed=seed)

    (
        X_train, y_train,
        X_val,   y_val,
        X_test,  y_test,
        feat_cols,
        scaler,
        le,
        class_names,
    ) = get_feature_matrices(train_df, val_df, test_df, log1p=log1p)

    return {
        "X_train": X_train, "y_train": y_train,
        "X_val":   X_val,   "y_val":   y_val,
        "X_test":  X_test,  "y_test":  y_test,
        "feat_cols": feat_cols,
        "scaler":    scaler,
        "le":        le,
        "class_names": class_names,
        "data_hash":   data_hash,
        "train_df":    train_df,
        "val_df":      val_df,
        "test_df":     test_df,
        "full_df":     df,
        "seed":        seed,
        "attack_families": ATTACK_FAMILIES,
        "label_map":       LABEL_MAP,
        "split_type": "stratified_random",
        "split_warning": "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic.",
        "row_counts": {"train": len(train_df), "validation": len(val_df), "test": len(test_df)},
        "log1p": log1p,
    }


if __name__ == "__main__":
    p = build_full_pipeline()
    print(f"\ndata_hash = {p['data_hash']}")
    print(f"X_train  = {p['X_train'].shape}")
    print(f"X_val    = {p['X_val'].shape}")
    print(f"X_test   = {p['X_test'].shape}")

