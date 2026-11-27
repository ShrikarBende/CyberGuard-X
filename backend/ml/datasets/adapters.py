"""Adapters for external flow datasets using the project's canonical schema.

Adapters preserve source labels and capture provenance. They do not claim that
similarly named features were generated with identical CICFlowMeter versions.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
from pathlib import Path
import re
from typing import Protocol

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


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
    max_rows_per_capture: int = 50_000
    sampling_seed: int = 42
    read_chunk_rows: int = 100_000

    def __post_init__(self):
        if self.max_rows_per_capture < 1 or self.read_chunk_rows < 1:
            raise ValueError("CSE capture row limits must be positive")

    def _capture_seed(self, path: Path) -> int:
        name_hash = int.from_bytes(hashlib.sha256(path.name.encode("utf-8")).digest()[:4], "big")
        return (int(self.sampling_seed) + name_hash) % (2**32)

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

    def load_capture(self, path: Path, *, keep_columns: list[str] | None = None) -> pd.DataFrame:
        path = Path(path)
        rng = np.random.default_rng(self._capture_seed(path))
        attack_parts: list[pd.DataFrame] = []
        benign_reservoir = pd.DataFrame()
        benign_keys = np.empty(0, dtype=np.float64)
        label_counts: dict[str, int] = {}
        numeric_columns: list[str] = []
        source_rows = 0
        dropped_nonfinite_rows = 0
        source_offset = 0

        for frame in pd.read_csv(path, low_memory=False, chunksize=self.read_chunk_rows):
            frame.columns = [str(c).strip() for c in frame.columns]
            label_column = next((c for c in ("Label", "label") if c in frame.columns), None)
            if label_column is None:
                raise ValueError(f"CSE capture {path.name} has no Label column")
            source_rows += len(frame)
            result = frame.rename(columns=CSE_FEATURE_COLUMNS)
            result["_source_row"] = np.arange(source_offset, source_offset + len(result), dtype=np.int64)
            source_offset += len(result)
            result["raw_label"] = frame[label_column].astype(str).str.strip()
            result["Label"] = frame[label_column].map(normalize_cse_label)
            result["_capture_file"] = path.name
            result["_capture_day"] = _capture_day(path)
            if "Timestamp" in result.columns:
                result["Timestamp"] = pd.to_datetime(
                    result["Timestamp"], errors="coerce", utc=True, dayfirst=True,
                )

            # Keep corrupt strings fatal; only parsed NaN/inf feature values are filtered.
            numeric_columns = list(dict.fromkeys(
                column for column in CSE_FEATURE_COLUMNS.values() if column in result.columns
            ))
            for column in numeric_columns:
                original = result[column]
                converted = pd.to_numeric(original, errors="coerce")
                invalid = original.notna() & converted.isna()
                if invalid.any():
                    raise ValueError(f"CSE capture {path.name} has non-numeric values in {column!r}")
                result[column] = converted

            if numeric_columns:
                numeric = result[numeric_columns].replace([np.inf, -np.inf], np.nan)
                invalid_rows = numeric.isna().any(axis=1)
                dropped_nonfinite_rows += int(invalid_rows.sum())
                result.loc[:, numeric_columns] = numeric
                result = result.loc[~invalid_rows].copy()
            for column in numeric_columns:
                result[column] = result[column].astype(np.float32)
            numeric_values = result[numeric_columns].to_numpy(dtype=np.float32, copy=False)
            if numeric_values.size and not np.isfinite(numeric_values).all():
                raise ValueError(f"CSE capture {path.name} contains non-finite feature values after filtering")

            for label, count in result["Label"].value_counts().items():
                key = str(label)
                label_counts[key] = label_counts.get(key, 0) + int(count)
            attack_mask = result["Label"] != "BENIGN"
            if attack_mask.any():
                attack_parts.append(result.loc[attack_mask].copy())
            benign = result.loc[~attack_mask].copy()
            if not benign.empty:
                new_keys = rng.random(len(benign))
                candidates = pd.concat([benign_reservoir, benign], ignore_index=True)
                candidate_keys = np.concatenate([benign_keys, new_keys])
                if len(candidates) > self.max_rows_per_capture:
                    selected = np.argpartition(candidate_keys, self.max_rows_per_capture - 1)[:self.max_rows_per_capture]
                    benign_reservoir = candidates.iloc[selected].copy()
                    benign_keys = candidate_keys[selected]
                else:
                    benign_reservoir = candidates
                    benign_keys = candidate_keys

        if source_rows == 0:
            raise ValueError(f"CSE capture {path.name} contains no rows")
        attacks = pd.concat(attack_parts, ignore_index=True) if attack_parts else pd.DataFrame()
        attack_rows = len(attacks)
        # The cap applies to the majority BENIGN class; attack rows are retained
        # in full even when that makes the final capture exceed the cap.
        benign_limit = self.max_rows_per_capture
        if len(benign_reservoir) > benign_limit:
            if benign_limit:
                selected = np.argpartition(benign_keys, benign_limit - 1)[:benign_limit]
                benign_reservoir = benign_reservoir.iloc[selected].copy()
            else:
                benign_reservoir = benign_reservoir.iloc[:0].copy()
        sampled_out_benign = label_counts.get("BENIGN", 0) - len(benign_reservoir)
        result = pd.concat([attacks, benign_reservoir], ignore_index=True)
        result = result.sort_values("_source_row", kind="stable").drop(columns=["_source_row"]).reset_index(drop=True)

        if dropped_nonfinite_rows:
            logger.warning(
                "CSE capture %s: dropped exactly %d rows with NaN or non-finite required numeric features",
                path.name, dropped_nonfinite_rows,
            )
        if sampled_out_benign:
            logger.info(
                "CSE capture %s: retained all %d attack rows and sampled %d/%d BENIGN rows (seed=%d, target cap=%d)",
                path.name, attack_rows, len(benign_reservoir), label_counts.get("BENIGN", 0),
                self._capture_seed(path), self.max_rows_per_capture,
            )
        ingestion = {
            "capture_file": path.name,
            "capture_day": _capture_day(path),
            "source_rows": source_rows,
            "dropped_nonfinite_rows": dropped_nonfinite_rows,
            "cleaned_rows": sum(label_counts.values()),
            "attack_rows_retained": attack_rows,
            "benign_rows_cleaned": label_counts.get("BENIGN", 0),
            "benign_rows_retained": len(benign_reservoir),
            "benign_rows_sampled_out": sampled_out_benign,
            "retained_rows": len(result),
            "max_benign_rows_per_capture": self.max_rows_per_capture,
            "sampling_seed": self._capture_seed(path),
            "label_counts_before_sampling": label_counts,
        }
        if keep_columns is not None:
            selected_columns = [column for column in keep_columns if column in result.columns]
            result = result.loc[:, selected_columns].copy()
        result.attrs["cse_ingestion"] = ingestion
        return result

    def load_all(self, *, keep_columns: list[str] | None = None) -> pd.DataFrame:
        frames = [self.load_capture(path, keep_columns=keep_columns) for path in self.capture_files()]
        result = pd.concat(frames, ignore_index=True)
        result.attrs["cse_ingestion"] = summarize_cse_ingestion(
            [frame.attrs["cse_ingestion"] for frame in frames],
            max_rows_per_capture=self.max_rows_per_capture,
            sampling_seed=self.sampling_seed,
        )
        return result

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


def summarize_cse_ingestion(captures: list[dict], *, max_rows_per_capture: int, sampling_seed: int) -> dict:
    """Summarize cleaning and sampling so evaluation reports retain provenance."""
    total_keys = (
        "source_rows", "dropped_nonfinite_rows", "cleaned_rows", "attack_rows_retained",
        "benign_rows_cleaned", "benign_rows_retained", "benign_rows_sampled_out", "retained_rows",
    )
    totals = {key: sum(int(capture.get(key, 0)) for capture in captures) for key in total_keys}
    return {
        "sampling": {
            "method": "retain every non-BENIGN row; deterministic reservoir-sample BENIGN rows to the per-capture cap",
            "max_benign_rows_per_capture": int(max_rows_per_capture),
            "seed": int(sampling_seed),
            "feature_dtype": "float32",
        },
        "totals": totals,
        "captures": captures,
    }


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
