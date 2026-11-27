"""Adapters for external flow datasets using the project's canonical schema.

Adapters preserve source labels and capture provenance. They do not claim that
similarly named features were generated with identical CICFlowMeter versions.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Protocol

import numpy as np
import pandas as pd


class DatasetAdapter(Protocol):
    """Minimal contract shared by file-backed network datasets."""

    name: str
    root: Path

    def capture_files(self) -> list[Path]: ...
    def load_capture(self, path: Path) -> pd.DataFrame: ...


# Canonical names match CICIDS2017's unsanitized flow columns where applicable.
CSE_FEATURE_COLUMNS = {
    "Dst Port": "Destination Port", "Protocol": "Protocol", "Flow Duration": "Flow Duration",
    "Tot Fwd Pkts": "Total Fwd Packets", "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets", "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max", "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean", "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max", "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean", "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s", "Flow Pkts/s": "Flow Packets/s",
    "Flow IAT Mean": "Flow IAT Mean", "Flow IAT Std": "Flow IAT Std",
    "Flow IAT Max": "Flow IAT Max", "Flow IAT Min": "Flow IAT Min",
    "Fwd IAT Tot": "Fwd IAT Total", "Fwd IAT Mean": "Fwd IAT Mean",
    "Fwd IAT Std": "Fwd IAT Std", "Fwd IAT Max": "Fwd IAT Max", "Fwd IAT Min": "Fwd IAT Min",
    "Bwd IAT Tot": "Bwd IAT Total", "Bwd IAT Mean": "Bwd IAT Mean",
    "Bwd IAT Std": "Bwd IAT Std", "Bwd IAT Max": "Bwd IAT Max", "Bwd IAT Min": "Bwd IAT Min",
    "Fwd PSH Flags": "Fwd PSH Flags", "Bwd PSH Flags": "Bwd PSH Flags",
    "Fwd URG Flags": "Fwd URG Flags", "Bwd URG Flags": "Bwd URG Flags",
    "Fwd Header Len": "Fwd Header Length", "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s", "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length", "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean", "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance", "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count", "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count", "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count", "CWE Flag Count": "CWE Flag Count",
    "ECE Flag Cnt": "ECE Flag Count", "Down/Up Ratio": "Down/Up Ratio",
    "Pkt Size Avg": "Average Packet Size", "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size", "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk", "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk", "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate", "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes", "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes", "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward", "Fwd Act Data Pkts": " act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward", "Active Mean": "Active Mean",
    "Active Std": "Active Std", "Active Max": "Active Max", "Active Min": "Active Min",
    "Idle Mean": "Idle Mean", "Idle Std": "Idle Std", "Idle Max": "Idle Max", "Idle Min": "Idle Min",
}

_LABELS = {
    "benign": "BENIGN", "bot": "Bot", "botnet ares": "Bot",
    "ftp-bruteforce": "BruteForce", "ftp-brute force": "BruteForce",
    "ssh-bruteforce": "BruteForce", "ssh-brute force": "BruteForce",
    "brute force -web": "WebAttack", "brute force -xss": "WebAttack",
    "sql injection": "WebAttack", "sql injection -auth": "WebAttack",
    "dos attacks-hulk": "DosDDoS", "dos attacks-slowhttptest": "DosDDoS",
    "dos attacks-goldeneye": "DosDDoS", "dos attacks-slowloris": "DosDDoS",
    "ddos attacks-loic-http": "DosDDoS", "ddos attacks-hoic": "DosDDoS",
    "ddos attack-loic-http": "DosDDoS", "ddos attack-hoic": "DosDDoS",
    "infiltration": "Infiltration", "portscan": "PortScan",
}
_DATE = re.compile(r"(?<!\d)(20\d{2})[-_]?([01]\d)[-_]?([0-3]\d)(?!\d)")
_DAY_FIRST_DATE = re.compile(r"(?<!\d)([0-3]\d)[-_]([01]\d)[-_](20\d{2})(?!\d)")


def normalize_cse_label(value: object) -> str:
    """Map only explicit label spellings; unknown/mixed labels fail closed."""
    raw = str(value).strip()
    key = re.sub(r"\s+", " ", raw.lower())
    if key == "infilteration":
        key = "infiltration"  # spelling used in the published label field
    if key not in _LABELS:
        raise ValueError(f"Unsupported CSE-CIC-IDS2018 label: {raw!r}")
    return _LABELS[key]


def _capture_day(path: Path) -> str:
    match = _DATE.search(path.name)
    if match:
        return f"{match[1]}-{match[2]}-{match[3]}"
    day_first = _DAY_FIRST_DATE.search(path.name)
    return "unknown" if not day_first else f"{day_first[3]}-{day_first[2]}-{day_first[1]}"


@dataclass(frozen=True)
class CSECICIDS2018Adapter:
    """Adapter for locally placed CSE-CIC-IDS2018 processed traffic CSVs."""

    root: Path = Path(__file__).resolve().parents[2] / "datasets" / "cse_cic_ids2018" / "processed"
    name: str = "CSE-CIC-IDS2018"

    def capture_files(self) -> list[Path]:
        if not self.root.is_dir():
            raise FileNotFoundError(
                f"CSE-CIC-IDS2018 CSV directory not found: {self.root}. "
                "Place the processed per-day CSV files there; see docs/PHASE3_DATA_PLAN.md."
            )
        paths = sorted(p for p in self.root.rglob("*.csv") if p.is_file())
        if not paths:
            raise FileNotFoundError(
                f"No CSE-CIC-IDS2018 CSV files found under {self.root}. "
                "Place processed per-day CSV files there; see docs/PHASE3_DATA_PLAN.md."
            )
        return paths

    def load_capture(self, path: Path) -> pd.DataFrame:
        path = Path(path)
        frame = pd.read_csv(path, low_memory=False)
        frame.columns = [str(c).strip() for c in frame.columns]
        label_column = next((c for c in ("Label", "label") if c in frame.columns), None)
        if label_column is None:
            raise ValueError(f"CSE capture {path.name} has no Label column")
        result = frame.rename(columns=CSE_FEATURE_COLUMNS)
        result["raw_label"] = result[label_column].astype(str).str.strip()
        result["Label"] = result[label_column].map(normalize_cse_label)
        result["_capture_file"] = path.name
        result["_capture_day"] = _capture_day(path)
        if "Timestamp" in result.columns:
            result["Timestamp"] = pd.to_datetime(result["Timestamp"], errors="coerce", utc=True)
        # Data values are parsed strictly: a non-numeric feature is a schema error.
        for column in CSE_FEATURE_COLUMNS.values():
            if column in result:
                converted = pd.to_numeric(result[column], errors="coerce")
                invalid = result[column].notna() & converted.isna()
                if invalid.any():
                    raise ValueError(f"CSE capture {path.name} has non-numeric values in {column!r}")
                result[column] = converted
        numeric = result.select_dtypes(include=[np.number])
        if not np.isfinite(numeric.to_numpy(dtype=np.float64)).all():
            raise ValueError(f"CSE capture {path.name} contains non-finite feature values")
        return result

    def load_all(self) -> pd.DataFrame:
        frames = [self.load_capture(path) for path in self.capture_files()]
        return pd.concat(frames, ignore_index=True)

    def capture_inventory(self) -> dict[str, dict[str, object]]:
        inventory: dict[str, dict[str, object]] = {}
        for path in self.capture_files():
            frame = self.load_capture(path)
            day = str(frame["_capture_day"].iloc[0]) if len(frame) else _capture_day(path)
            row = inventory.setdefault(day, {"files": [], "flows": 0, "families": {}, "family_files": {}})
            row["files"].append(path.name)
            row["flows"] += int(len(frame))
            counts = frame["Label"].value_counts().to_dict()
            for family, count in counts.items():
                row["families"][family] = row["families"].get(family, 0) + int(count)
                row["family_files"].setdefault(family, []).append(path.name)
        return inventory


@dataclass(frozen=True)
class UNSWNB15Adapter:
    """Optional network mapping for UNSW-NB15's supplied categorical schema."""
    root: Path = Path(__file__).resolve().parents[2] / "datasets" / "unsw_nb15"
    name: str = "UNSW-NB15"

    def capture_files(self) -> list[Path]:
        return sorted(self.root.glob("UNSW-NB15_[1-4].csv"))

    def load_capture(self, path: Path) -> pd.DataFrame:
        from ml.sequence_graph import UNSW_COLUMNS
        frame = pd.read_csv(path, header=None, names=UNSW_COLUMNS, low_memory=False, encoding="latin-1")
        frame["Label"] = np.where(pd.to_numeric(frame["label"], errors="coerce").fillna(0) == 0, "BENIGN", "Attack")
        frame["_capture_file"] = Path(path).name
        frame["raw_label"] = frame["attack_cat"].fillna("").astype(str)
        return frame
