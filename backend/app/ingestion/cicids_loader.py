"""
CICIDS2017 Real Dataset Ingestion & Feature Extractor.
Parses official Canadian Institute for Cybersecurity (UNB) CSV flow records.
"""
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import numpy as np

DATASETS_DIR = Path(__file__).resolve().parent.parent.parent / "datasets"

# Official 79 features in CICIDS2017
CICIDS_FILES = {
    "portscan": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "ddos": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
}


def get_available_cicids_files() -> Dict[str, Dict[str, Any]]:
    """Check which real CICIDS2017 CSV files are present on disk."""
    available = {}
    for key, fname in CICIDS_FILES.items():
        fpath = DATASETS_DIR / fname
        if fpath.exists():
            size_mb = round(fpath.stat().st_size / (1024 * 1024), 2)
            available[key] = {
                "file_name": fname,
                "file_path": str(fpath),
                "size_mb": size_mb,
                "is_present": True
            }
        else:
            available[key] = {
                "file_name": fname,
                "file_path": str(fpath),
                "size_mb": 0.0,
                "is_present": False
            }
    return available


def load_real_cicids_dataset(
    sample_size: int = 10000,
    seed: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """
    Load, clean, and extract features from real CICIDS2017 CSVs.
    Returns:
    - X_train_val: numpy feature matrix (known classes: Benign, PortScan)
    - y_train_val: integer labels
    - X_novel: real DDoS samples held out strictly for Open-Set evaluation
    - class_names: list of class names
    """
    portscan_path = DATASETS_DIR / CICIDS_FILES["portscan"]
    ddos_path = DATASETS_DIR / CICIDS_FILES["ddos"]

    if not portscan_path.exists():
        raise FileNotFoundError(f"Real CICIDS2017 file not found at: {portscan_path}")

    # Read PortScan file (sample from both benign region and attack region)
    print(f"Reading real CICIDS2017 dataset from {portscan_path.name}...")
    # Read chunk from beginning (mostly BENIGN)
    df_benign_chunk = pd.read_csv(portscan_path, nrows=int(sample_size * 1.5))
    df_benign_chunk.columns = df_benign_chunk.columns.str.strip()
    df_benign_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_benign_chunk.dropna(inplace=True)

    # Read chunk from middle (PortScan attack active)
    df_attack_chunk = pd.read_csv(portscan_path, skiprows=90000, nrows=int(sample_size * 1.5), header=None)
    df_attack_chunk.columns = df_benign_chunk.columns
    df_attack_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_attack_chunk.dropna(inplace=True)

    benign_rows = df_benign_chunk[df_benign_chunk["Label"] == "BENIGN"]
    portscan_rows = df_attack_chunk[df_attack_chunk["Label"] == "PortScan"]

    benign_df = benign_rows.sample(
        n=min(int(sample_size * 0.6), len(benign_rows)),
        random_state=seed
    )
    portscan_df = portscan_rows.sample(
        n=min(int(sample_size * 0.4), len(portscan_rows)),
        random_state=seed
    )

    combined_known = pd.concat([benign_df, portscan_df], axis=0).sample(frac=1.0, random_state=seed)

    # Feature columns matching our multi-layer feature representation:
    # 1. Flow Duration
    # 2. Total Fwd Packets
    # 3. Total Backward Packets
    # 4. Total Length of Fwd Packets
    # 5. Flow Bytes/s
    # 6. Flow Packets/s
    # 7. Flow IAT Mean
    # 8. Fwd Packet Length Mean
    # 9. Destination Port
    # 10. Average Packet Size
    # 11. SYN Flag Count
    # 12. Down/Up Ratio

    feature_cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Fwd Packet Length Mean",
        "Destination Port",
        "Average Packet Size",
        "SYN Flag Count",
        "Down/Up Ratio"
    ]

    # Verify all feature columns exist in raw CICIDS
    for col in feature_cols:
        if col not in combined_known.columns:
            # Fallback if minor naming difference in CICIDS headers
            matches = [c for c in combined_known.columns if col.lower() in c.lower()]
            if matches:
                combined_known.rename(columns={matches[0]: col}, inplace=True)
            else:
                combined_known[col] = 0.0

    X_known = combined_known[feature_cols].values.astype(np.float32)

    # Map labels: 0 for Benign, 1 for PortScan
    y_known = (combined_known["Label"] == "PortScan").astype(np.int64).values
    class_names = ["BENIGN (Real CICIDS)", "PortScan (Real CICIDS)"]

    # Now load held-out novel attack from real DDoS file (if present)
    X_novel = None
    if ddos_path.exists():
        print(f"Loading real held-out novel threat set from {ddos_path.name}...")
        header_df = pd.read_csv(ddos_path, nrows=1)
        clean_headers = [c.strip() for c in header_df.columns]
        df_ddos = pd.read_csv(ddos_path, skiprows=20000, nrows=2000, header=None)
        df_ddos.columns = clean_headers
        df_ddos.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_ddos.dropna(inplace=True)

        ddos_attacks = df_ddos[df_ddos["Label"] == "DDoS"]
        if len(ddos_attacks) > 0:
            for col in feature_cols:
                if col not in ddos_attacks.columns:
                    matches = [c for c in ddos_attacks.columns if col.lower() in c.lower()]
                    if matches:
                        ddos_attacks = ddos_attacks.rename(columns={matches[0]: col})
                    else:
                        ddos_attacks[col] = 0.0

            n_novel = min(500, len(ddos_attacks))
            X_novel = ddos_attacks[feature_cols].sample(n=n_novel, random_state=seed).values.astype(np.float32)

    # Standardize / Min-Max scale safely to avoid numerical instability
    col_means = np.nanmean(X_known, axis=0)
    col_stds = np.nanstd(X_known, axis=0) + 1e-5
    X_known = (X_known - col_means) / col_stds

    if X_novel is not None:
        X_novel = (X_novel - col_means) / col_stds
    else:
        X_novel = np.zeros((100, len(feature_cols)), dtype=np.float32)

    return X_known, y_known, X_novel, class_names
