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
import gc
import json
import os
import sys
import warnings
from collections import Counter, OrderedDict, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


class HostWindowAggregator:
    """Bounded per-source behavioral context over a rolling 60-second flow window."""
    def __init__(self, window_seconds: int = 60, max_events_per_source: int = 2048,
                 max_sources: int = 4096, short_flow_bytes: int = 64):
        self.window = timedelta(seconds=window_seconds)
        self.max_events_per_source = max(1, int(max_events_per_source))
        self.max_sources = max(1, int(max_sources))
        self.short_flow_bytes = int(short_flow_bytes)
        self._flows: OrderedDict[str, deque] = OrderedDict()
        self._stats: dict[str, dict] = {}

    @staticmethod
    def _value(row, *names, default=None):
        for name in names:
            if name in row and pd.notna(row[name]):
                return row[name]
        return default

    def update(self, flow) -> dict[str, float]:
        row = dict(flow)
        source = str(self._value(row, "Source IP", "source_ip", "Src IP", "src_ip", "srcip", default=""))
        raw_time = self._value(row, "Timestamp", "timestamp", "flow_start", "Flow Start", default=None)
        try:
            stamp = pd.to_datetime(raw_time, utc=True).to_pydatetime() if raw_time is not None else None
        except (TypeError, ValueError):
            stamp = None
        if not source or stamp is None or pd.isna(stamp):
            return self._zero_features()
        destination_port = self._value(row, "Destination Port", "destination_port", "dst_port", "dstport")
        destination_ip = self._value(row, "Destination IP", "destination_ip", "Dst IP", "dst_ip", "dstip")
        syn_total = float(self._value(row, "SYN Flag Count", "syn_flag_count", "syn_count", default=0) or 0)
        syn_ack = float(self._value(row, "SYN-ACK Flag Count", "SYN ACK Flag Count", "syn_ack_flag_count", default=0) or 0)
        syn = max(syn_total - syn_ack, 0.0)
        ack = float(self._value(row, "ACK Flag Count", "ack_flag_count", "ack_count", default=0) or 0)
        byte_count = self._value(row, "bytes_transferred")
        if byte_count is None:
            fwd = self._value(row, "Total Length of Fwd Packets", "total_length_fwd_packets", default=0) or 0
            bwd = self._value(row, "Total Length of Bwd Packets", "total_length_bwd_packets", default=0) or 0
            byte_count = float(fwd) + float(bwd)
        byte_count = float(byte_count or 0)
        syn_only = bool(self._value(row, "syn_only", "syn_only_short_flow", default=(syn > 0 and ack <= 0 and byte_count <= self.short_flow_bytes)))
        return self.update_values(source, stamp, destination_port, destination_ip, syn, ack, byte_count, syn_only)

    @staticmethod
    def _zero_features() -> dict[str, float]:
        return {"distinct_dst_ports_1m": 0.0, "syn_to_ack_ratio": 0.0,
                "flow_inter_arrival_variance": 0.0, "mean_bytes_per_flow": 0.0,
                "win_unique_dst_ports_60s": 0.0, "win_unique_dst_ips_60s": 0.0,
                "win_syn_only_ratio_60s": 0.0, "win_flow_rate_60s": 0.0,
                "suspicious_flows_60s": 0.0}

    def _remove_oldest(self, source: str) -> None:
        flows = self._flows[source]
        stats = self._stats[source]
        oldest = flows.popleft()
        _, port, destination, syn, ack, byte_count, syn_only, delta = oldest
        if port is not None:
            stats["ports"][port] -= 1
            if stats["ports"][port] <= 0:
                del stats["ports"][port]
        if destination:
            stats["ips"][destination] -= 1
            if stats["ips"][destination] <= 0:
                del stats["ips"][destination]
        stats["syn"] -= syn
        stats["ack"] -= ack
        stats["bytes"] -= byte_count
        stats["short"] -= int(syn_only)
        if delta:
            stats["delta_sum"] -= delta
            stats["delta_sq_sum"] -= delta * delta
            stats["delta_count"] -= 1
        # The next item's interval had included the row just removed.
        if flows and flows[0][7]:
            next_item = flows[0]
            prior_delta = next_item[7]
            stats["delta_sum"] -= prior_delta
            stats["delta_sq_sum"] -= prior_delta * prior_delta
            stats["delta_count"] -= 1
            flows[0] = (*next_item[:7], 0.0)

    def update_values(self, source: str, stamp, destination_port, destination_ip,
                      syn: float, ack: float, byte_count: float, syn_only: bool) -> dict[str, float]:
        """Fast scalar update used by both streaming events and batch dataframe extraction."""
        if not source or stamp is None or pd.isna(stamp):
            return self._zero_features()
        source = str(source)
        if source not in self._flows:
            if len(self._flows) >= self.max_sources:
                old_source, _ = self._flows.popitem(last=False)
                self._stats.pop(old_source, None)
            self._flows[source] = deque()
            self._stats[source] = {"ports": Counter(), "ips": Counter(), "syn": 0.0, "ack": 0.0,
                                   "bytes": 0.0, "short": 0, "delta_sum": 0.0,
                                   "delta_sq_sum": 0.0, "delta_count": 0}
        self._flows.move_to_end(source)
        flows, stats = self._flows[source], self._stats[source]
        delta = max(0.0, (stamp - flows[-1][0]).total_seconds()) if flows else 0.0
        while len(flows) >= self.max_events_per_source:
            self._remove_oldest(source)
        item = (stamp, destination_port, destination_ip, float(syn), float(ack),
                float(byte_count), bool(syn_only), delta)
        flows.append(item)
        if destination_port is not None:
            stats["ports"][destination_port] += 1
        if destination_ip:
            stats["ips"][destination_ip] += 1
        stats["syn"] += float(syn)
        stats["ack"] += float(ack)
        stats["bytes"] += float(byte_count)
        stats["short"] += int(bool(syn_only))
        if delta:
            stats["delta_sum"] += delta
            stats["delta_sq_sum"] += delta * delta
            stats["delta_count"] += 1
        cutoff = stamp - self.window
        while flows and flows[0][0] < cutoff:
            self._remove_oldest(source)
        count = len(flows)
        variance = (stats["delta_sq_sum"] / stats["delta_count"] -
                    (stats["delta_sum"] / stats["delta_count"]) ** 2) if stats["delta_count"] else 0.0
        return {
            "distinct_dst_ports_1m": float(len(stats["ports"])),
            "syn_to_ack_ratio": float(stats["syn"] / max(stats["ack"], 1.0)),
            "flow_inter_arrival_variance": float(max(variance, 0.0)),
            "mean_bytes_per_flow": float(stats["bytes"] / count) if count else 0.0,
            "win_unique_dst_ports_60s": float(len(stats["ports"])),
            "win_unique_dst_ips_60s": float(len(stats["ips"])),
            "win_syn_only_ratio_60s": float(stats["short"] / count) if count else 0.0,
            "win_flow_rate_60s": float(count / max(self.window.total_seconds(), 1.0)),
            "suspicious_flows_60s": float(stats["short"]),
        }


def enrich_flow_with_host_context(flow_df: pd.DataFrame, aggregator: HostWindowAggregator) -> pd.DataFrame:
    """Append rolling source host features only when identifiers and time exist.

    CICIDS2017's MachineLearningCVE export omits source IP and timestamp. In
    that case these derived columns are not part of the model matrix at all.
    Rows with partially missing values still receive zero context, but only
    after the capture has demonstrated that the required fields are available.
    """
    # The operation only adds feature columns; a deep copy of a multi-million
    # row capture needlessly duplicates every raw CICIDS column in memory.
    # A shallow frame copy keeps the caller's columns intact while isolating
    # the returned frame's column assignments.
    result = flow_df.copy(deep=False)
    names = ["distinct_dst_ports_1m", "syn_to_ack_ratio", "flow_inter_arrival_variance", "mean_bytes_per_flow",
             "win_unique_dst_ports_60s", "win_unique_dst_ips_60s", "win_syn_only_ratio_60s", "win_flow_rate_60s"]
    timestamp_column = next((name for name in ("Timestamp", "timestamp", "flow_start", "Flow Start") if name in result), None)
    source_column = _find_column(result, ("Source IP", "source_ip", "Src IP", "src_ip", "srcip"))
    if result.empty or timestamp_column is None or source_column is None:
        return result
    parsed_times = pd.to_datetime(result[timestamp_column], errors="coerce", utc=True)
    usable_sources = result[source_column].notna() & result[source_column].astype(str).str.strip().ne("")
    if not (usable_sources & parsed_times.notna()).any():
        return result
    if timestamp_column:
        timestamps = parsed_times
        timestamp_ns = timestamps.astype("int64", copy=False).to_numpy()
        positions = np.argsort(timestamp_ns, kind="mergesort")
    else:
        timestamp_ns = np.full(len(result), np.iinfo(np.int64).min, dtype=np.int64)
        positions = np.arange(len(result))
    def column_values(aliases, default, *, numeric=False):
        column = _find_column(result, aliases)
        if column is None:
            return np.full(len(result), default)
        values = result[column]
        if numeric:
            return pd.to_numeric(values, errors="coerce").fillna(default).to_numpy(dtype=np.float64)
        return values.fillna(default).astype(str).to_numpy()
    sources = column_values(("Source IP", "source_ip", "Src IP", "src_ip", "srcip"), "")
    destinations = column_values(("Destination IP", "destination_ip", "Dst IP", "dst_ip", "dstip"), "")
    ports = column_values(("Destination Port", "destination_port", "dst_port", "dstport"), -1, numeric=True)
    syn = column_values(("SYN Flag Count", "syn_flag_count", "syn_count"), 0.0, numeric=True)
    syn_ack = column_values(("SYN-ACK Flag Count", "SYN ACK Flag Count", "syn_ack_flag_count"), 0.0, numeric=True)
    ack = column_values(("ACK Flag Count", "ack_flag_count", "ack_count"), 0.0, numeric=True)
    bytes_col = _find_column(result, ("bytes_transferred",))
    if bytes_col:
        byte_count = pd.to_numeric(result[bytes_col], errors="coerce").fillna(0).to_numpy(dtype=np.float64)
    else:
        fwd = column_values(("Total Length of Fwd Packets", "total_length_fwd_packets"), 0.0, numeric=True)
        bwd = column_values(("Total Length of Bwd Packets", "total_length_bwd_packets"), 0.0, numeric=True)
        byte_count = fwd + bwd
    explicit_short_column = _find_column(result, ("syn_only", "syn_only_short_flow"))
    explicit_short = (result[explicit_short_column].fillna(False).astype(bool).to_numpy()
                      if explicit_short_column else None)
    features: list[dict | None] = [None] * len(result)
    invalid_time = np.iinfo(np.int64).min
    for position in positions:
        stamp_ns = timestamp_ns[position]
        if stamp_ns == invalid_time or not sources[position]:
            features[position] = aggregator._zero_features()
            continue
        stamp = datetime.fromtimestamp(stamp_ns / 1_000_000_000, tz=timezone.utc)
        syn_only = (bool(explicit_short[position]) if explicit_short is not None else
                    bool(max(syn[position] - syn_ack[position], 0.0) > 0 and ack[position] <= 0 and
                         byte_count[position] <= aggregator.short_flow_bytes))
        port = None if ports[position] < 0 else int(ports[position])
        dest = destinations[position] or None
        features[position] = aggregator.update_values(
            sources[position], stamp, port, dest, max(syn[position] - syn_ack[position], 0.0),
            ack[position], byte_count[position], syn_only,
        )
    for name in names:
        result[name] = [float(item.get(name, 0.0)) for item in features]
    return result


SESSION_LEAK_COLUMNS = frozenset({
    "flow id", "source ip", "destination ip", "src ip", "dst ip", "source port", "src port",
    "timestamp", "simillarhttp", "capture offset", "capture offset seconds", "packet capture id",
    "capture id", "pcap id", "source file",
})
SESSION_INVARIANT_DROP_COLS = SESSION_LEAK_COLUMNS | {"destination port", "dst port"}


def _find_column(df: pd.DataFrame, aliases: tuple[str, ...]) -> str | None:
    normalized = {str(column).strip().lower(): str(column) for column in df.columns}
    return next((normalized[alias.strip().lower()] for alias in aliases if alias.strip().lower() in normalized), None)


def add_protocol_invariant_features(frame: pd.DataFrame, *, sanitize_session_features: bool = False) -> pd.DataFrame:
    """Add flow IAT/asymmetry features and, when requested, bucket destination service ports."""
    iat_std = _find_column(frame, ("Flow IAT Std", "flow_iat_std"))
    iat_mean = _find_column(frame, ("Flow IAT Mean", "flow_iat_mean"))
    fwd = _find_column(frame, ("Total Length of Fwd Packets", "total_length_fwd_packets"))
    bwd = _find_column(frame, ("Total Length of Bwd Packets", "total_length_bwd_packets"))
    frame["iat_cv"] = (pd.to_numeric(frame[iat_std], errors="coerce").fillna(0) /
                        (pd.to_numeric(frame[iat_mean], errors="coerce").fillna(0) + 1e-6)) if iat_std and iat_mean else 0.0
    frame["fwd_bwd_byte_ratio"] = (pd.to_numeric(frame[fwd], errors="coerce").fillna(0) /
                                   (pd.to_numeric(frame[bwd], errors="coerce").fillna(0) + 1e-6)) if fwd and bwd else 0.0
    if sanitize_session_features:
        port = _find_column(frame, ("Destination Port", "destination_port", "dst_port"))
        port_values = pd.to_numeric(frame[port], errors="coerce").fillna(-1) if port else pd.Series(-1, index=frame.index)
        frame["is_well_known_port"] = ((port_values >= 0) & (port_values <= 1023)).astype(np.float32)
        frame["is_registered_port"] = ((port_values >= 1024) & (port_values <= 49151)).astype(np.float32)
        frame["is_ephemeral_port"] = (port_values >= 49152).astype(np.float32)
        blacklist = {name.strip().lower() for name in SESSION_INVARIANT_DROP_COLS}
        frame.drop(columns=[column for column in frame.columns if str(column).strip().lower() in blacklist],
                   inplace=True, errors="ignore")
    return frame


def add_service_port_buckets(frame: pd.DataFrame, fallback_ports=None) -> pd.DataFrame:
    """Add low-cardinality destination service flags without removing raw columns."""
    port = _find_column(frame, ("Destination Port", "destination_port", "dst_port", "dstport"))
    if port is not None:
        values = pd.to_numeric(frame[port], errors="coerce").fillna(-1)
    elif fallback_ports is not None:
        values = pd.to_numeric(pd.Series(fallback_ports, index=frame.index), errors="coerce").fillna(-1)
    else:
        values = pd.Series(-1, index=frame.index)
    frame["is_well_known_port"] = ((values >= 0) & (values <= 1023)).astype(np.float32)
    frame["is_registered_port"] = ((values >= 1024) & (values <= 49151)).astype(np.float32)
    frame["is_ephemeral_port"] = (values >= 49152).astype(np.float32)
    return frame

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
    return CACHE_DIR / (csv_path.stem + ".clean-v4.parquet")


def _remove_stale_cache_versions(current_path: Path, pattern: str) -> None:
    """Remove prior cache-version files only after the current file is durable."""
    for stale_path in CACHE_DIR.glob(pattern):
        if stale_path == current_path:
            continue
        stale_path.unlink(missing_ok=True)
        print(f"  [stale cache removed] {stale_path.name}")


def _combined_cache_paths(profile: str, sample: float) -> Tuple[Path, Path]:
    sample_key = f"{sample:.6f}".rstrip("0").rstrip(".")
    stem = f"cicids_{profile}_sample_{sample_key}_dedup-v4"
    return CACHE_DIR / f"{stem}.parquet", CACHE_DIR / f"{stem}.json"


def _row_hashes(df: pd.DataFrame, feature_cols: List[str], chunk_size: int = 200_000) -> np.ndarray:
    """Hash feature columns in bounded chunks."""
    hashes = np.empty(len(df), dtype=np.uint64)
    for start in range(0, len(df), chunk_size):
        block = df.iloc[start:start + chunk_size]
        hashes[start:start + len(block)] = pd.util.hash_pandas_object(
            block[feature_cols], index=False
        ).to_numpy(dtype=np.uint64, copy=False)
        del block
    return hashes


def _hash_sample_mask(df: pd.DataFrame, sample: float, chunk_size: int = 200_000) -> np.ndarray:
    """Select rows by the same feature hash used for deduplication."""
    feature_cols = [column for column in df.columns if column not in {LABEL_COL, "_source_file"}]
    hashes = _row_hashes(df, feature_cols, chunk_size=chunk_size)
    mask = hashes % np.uint64(100) < int(sample * 100)
    del hashes
    return mask


def _peak_memory_mb() -> float:
    """Return the process peak resident memory in MiB."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize / (1024 * 1024)
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 if sys.platform != "darwin" else 1024 * 1024)


def _load_one_csv(csv_path: Path, force_reload: bool = False) -> pd.DataFrame:
    """
    Load, clean, and cache one CICIDS2017 CSV as Parquet.
    - Strip column-name whitespace
    - Replace inf / -inf with NaN, drop NaN rows
    - Preserve duplicates for profile-aware cross-file deduplication
    - Map labels; drop excluded & unmapped labels
    """
    cache_path = _parquet_cache_path(csv_path)

    if not force_reload and cache_path.exists():
        print(f"  [cache hit] Loading {cache_path.name}")
        return pd.read_parquet(cache_path)

    print(f"  [csv read ] Reading {csv_path.name} ...")
    probe = pd.read_csv(csv_path, nrows=1000, low_memory=False)
    dtype_map = {}
    for raw_column, dtype in probe.dtypes.items():
        column = raw_column.strip()
        if column == LABEL_COL:
            dtype_map[raw_column] = str
        elif pd.api.types.is_float_dtype(dtype):
            dtype_map[raw_column] = np.float32
        elif pd.api.types.is_integer_dtype(dtype):
            dtype_map[raw_column] = dtype
    del probe
    gc.collect()
    df = pd.read_csv(csv_path, low_memory=False, dtype=dtype_map)

    # 1. Strip column whitespace
    df.columns = df.columns.str.strip()

    # 2. Replace inf/-inf with NaN, drop NaN rows
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before_nan = len(df)
    df.dropna(inplace=True)
    print(f"    NaN drop : {before_nan} -> {len(df)}")

    # 3. Map labels; handle unicode hyphen variants
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

    # Preserve float32 and integer dtypes; do not allow float64 columns.
    float_cols = df.select_dtypes(include=[np.float64]).columns
    if len(float_cols):
        df[float_cols] = df[float_cols].astype(np.float32)
    for column in df.select_dtypes(include=[np.integer]).columns:
        df[column] = pd.to_numeric(df[column], downcast="integer")

    # 7. Cache as Parquet
    df.to_parquet(cache_path, index=False)
    _remove_stale_cache_versions(cache_path, f"{csv_path.stem}.clean-v*.parquet")
    print(f"    Cached -> {cache_path.name}")
    return df


def load_all_cicids(force_reload: bool = False, sample: float = 1.0) -> pd.DataFrame:
    """
    Assert all 8 CSVs exist, load + clean each, return concatenated DataFrame.
    If any file is missing, raises FileNotFoundError and stops.
    """
    if not 0 < sample <= 1:
        raise ValueError("sample must be in (0, 1]")
    profile = "light" if sample < 1 else "full"
    cache_path, metadata_path = _combined_cache_paths(profile, sample)
    if not force_reload and cache_path.exists() and metadata_path.exists():
        print(f"[cache hit] Loading {cache_path.name}")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        cached = pd.read_parquet(cache_path)
        print(f"Deduplication: exact duplicate rows dropped={metadata['exact_dropped']:,}; "
              f"conflicting-label feature rows dropped={metadata['conflicts_dropped']:,}")
        print(f"Peak memory after step: {_peak_memory_mb():.1f} MiB")
        return cached

    missing = [f for f in CICIDS_FILES if not (DATASETS_DIR / f).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing CICIDS2017 files in {DATASETS_DIR}:\n" + "\n".join(missing)
        )

    parts = []
    for fname in CICIDS_FILES:
        csv_path = DATASETS_DIR / fname
        df = _load_one_csv(csv_path, force_reload=force_reload)
        df["_source_file"] = fname   # keep provenance
        if sample < 1:
            keep = _hash_sample_mask(df, sample)
            sampled = df.iloc[np.flatnonzero(keep)]
            del df, keep
            df = sampled
        parts.append(df)
        del df
        gc.collect()
    combined = pd.concat(parts, axis=0, ignore_index=True)
    del parts
    gc.collect()
    combined, exact_dropped, conflicts_dropped = deduplicate_flows(combined)
    print(f"Deduplication: exact duplicate rows dropped={exact_dropped:,}; "
          f"conflicting-label feature rows dropped={conflicts_dropped:,}")
    print(f"\nTotal rows after cleaning: {len(combined):,}")
    print("Label distribution:")
    print(combined[LABEL_COL].value_counts().to_string())
    combined.to_parquet(cache_path, index=False)
    metadata_path.write_text(json.dumps({
        "profile": profile, "sample_fraction": sample,
        "exact_dropped": exact_dropped, "conflicts_dropped": conflicts_dropped,
    }, indent=2) + "\n", encoding="utf-8")
    cache_prefix = cache_path.stem.rsplit("dedup-v", 1)[0]
    _remove_stale_cache_versions(cache_path, f"{cache_prefix}dedup-v*.parquet")
    _remove_stale_cache_versions(metadata_path, f"{cache_prefix}dedup-v*.json")
    print(f"[cache write] {cache_path.name}")
    print(f"Peak memory after step: {_peak_memory_mb():.1f} MiB")
    return combined


def deduplicate_flows(df: pd.DataFrame) -> Tuple[pd.DataFrame, int, int]:
    """Drop exact duplicates, then all feature-identical groups with label conflicts."""
    feature_cols = [c for c in df.columns if c not in {LABEL_COL, "_source_file"}]
    feature_hash = _row_hashes(df, feature_cols)
    labels = df[LABEL_COL].to_numpy(copy=False)
    pairs = pd.DataFrame({"feature_hash": feature_hash, "label": labels})
    exact_duplicate = pairs.duplicated(keep="first").to_numpy(dtype=bool, copy=False)
    exact_dropped = int(exact_duplicate.sum())
    unique_pairs = pairs.iloc[np.flatnonzero(~exact_duplicate)]
    conflict_counts = unique_pairs.groupby("feature_hash", sort=False)["label"].nunique()
    conflict_hashes = conflict_counts.index[conflict_counts > 1].to_numpy(dtype=np.uint64, copy=False)
    conflicting = np.isin(feature_hash, conflict_hashes, assume_unique=False)
    conflicts_dropped = int((~exact_duplicate & conflicting).sum())
    keep_mask = ~exact_duplicate & ~conflicting
    result = df.iloc[np.flatnonzero(keep_mask)]
    del feature_hash, labels, pairs, exact_duplicate, unique_pairs, conflict_counts
    del conflict_hashes, conflicting, keep_mask
    gc.collect()
    return result, exact_dropped, conflicts_dropped


def build_splits(
    df: pd.DataFrame,
    seed: int = 42,
    val_ratio: float = 0.10,
    test_ratio: float = 0.20,
    split_mode: str = "stratified_random",
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Per-file stratified split: 70% train | 10% val | 20% test.
    Scaler is NOT fitted here — that's done in get_feature_matrices().
    No Timestamp column exists in CICIDS2017; we use stratified split and warn.
    """
    if split_mode not in {"stratified_random", "session_disjoint"}:
        raise ValueError("split_mode must be 'stratified_random' or 'session_disjoint'")
    if split_mode == "session_disjoint":
        # CICIDS2017's source CSVs are capture-day/session files. Keep each
        # capture intact across splits; within a timestamped source, contiguous
        # half-day blocks are the smallest independent unit.
        work = df.copy()
        if "Timestamp" in work.columns:
            stamps = pd.to_datetime(work["Timestamp"], errors="coerce", dayfirst=True, utc=True)
            block = stamps.dt.floor("12h").astype(str)
            work["_session_group"] = work["_source_file"].astype(str) + "|" + block
            missing = stamps.isna()
            work.loc[missing, "_session_group"] = work.loc[missing, "_source_file"].astype(str) + "|unknown"
        else:
            work["_session_group"] = work["_source_file"].astype(str)
        groups = work["_session_group"].to_numpy()
        first, second = GroupShuffleSplit(n_splits=1, test_size=test_ratio, random_state=seed).split(work, groups=groups).__next__()
        train_val, test = work.iloc[first], work.iloc[second]
        val_fraction = val_ratio / (1.0 - test_ratio)
        train_idx, val_idx = next(GroupShuffleSplit(n_splits=1, test_size=val_fraction, random_state=seed + 1).split(train_val, groups=train_val["_session_group"]))
        train, val = train_val.iloc[train_idx], train_val.iloc[val_idx]
        train_groups, val_groups, test_groups = (set(train["_session_group"]), set(val["_session_group"]),
                                                set(test["_session_group"]))
        if (not train_groups.isdisjoint(val_groups) or not train_groups.isdisjoint(test_groups)
                or not val_groups.isdisjoint(test_groups)):
            raise AssertionError("session-disjoint split leaked a source/day block")
        train, val, test = train.drop(columns=["_session_group"]), val.drop(columns=["_session_group"]), test.drop(columns=["_session_group"])
        return train.reset_index(drop=True), val.reset_index(drop=True), test.reset_index(drop=True)
    warning = "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic."
    print(f"WARNING: {warning}")
    warnings.warn(
        warning,
        UserWarning,
        stacklevel=2,
    )

    train_frames, val_frames, test_frames = [], [], []

    # Iterating sorted provenance values matches groupby's default key order,
    # while avoiding groupby materializing a sorted copy of the full table.
    for source_file in sorted(df["_source_file"].unique()):
        group = df.loc[df["_source_file"] == source_file]
        labels = group[LABEL_COL]
        X_tv = None
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
        del group, labels, X_tv, X_test, X_train, X_val
        gc.collect()

    train_df = pd.concat(train_frames, ignore_index=True)
    val_df = pd.concat(val_frames, ignore_index=True)
    test_df = pd.concat(test_frames, ignore_index=True)
    return train_df, val_df, test_df


def _get_feature_cols(df: pd.DataFrame, sanitize_session_features: bool = False) -> List[str]:
    """Return all numeric feature columns (exclude Label and provenance cols)."""
    exclude = {LABEL_COL, "_source_file"}
    # select_dtypes materializes and consolidates a multi-million-row copy on
    # recent pandas versions. Inspect the dtype metadata directly instead.
    num_cols = [column for column, dtype in df.dtypes.items()
                if pd.api.types.is_numeric_dtype(dtype)]
    columns = [c for c in num_cols if c not in exclude]
    if sanitize_session_features:
        blacklist = {name.strip().lower() for name in SESSION_INVARIANT_DROP_COLS}
        columns = [c for c in columns if c.strip().lower() not in blacklist]
    return columns


def fit_log1p_columns(X_train: np.ndarray) -> np.ndarray:
    """Select non-negative feature columns using training data only."""
    return np.nanmin(X_train, axis=0) >= 0


def apply_log1p_columns(X: np.ndarray, columns: np.ndarray) -> np.ndarray:
    """Apply log1p to selected non-negative values, preserving any negatives."""
    selected = np.flatnonzero(columns)
    if not selected.size:
        return np.asarray(X, dtype=np.float32)
    result = np.asarray(X, dtype=np.float32).copy()
    values = result[:, selected]
    nonnegative = values >= 0
    values[nonnegative] = np.log1p(values[nonnegative])
    result[:, selected] = values
    return result


def _fit_transform_scaler_in_chunks(
    scaler: StandardScaler, X: np.ndarray, chunk_size: int = 100_000
) -> np.ndarray:
    """Fit and transform without a full-matrix float64 temporary."""
    for start in range(0, len(X), chunk_size):
        scaler.partial_fit(X[start:start + chunk_size])
    for start in range(0, len(X), chunk_size):
        end = min(start + chunk_size, len(X))
        X[start:end] = scaler.transform(X[start:end])
    return X


def _transform_scaler_in_chunks(scaler: StandardScaler, X: np.ndarray, chunk_size: int = 100_000) -> np.ndarray:
    for start in range(0, len(X), chunk_size):
        end = min(start + chunk_size, len(X))
        X[start:end] = scaler.transform(X[start:end])
    return X


def get_feature_matrices(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    log1p: bool = False,
    label_classes: list[str] | None = None,
    sanitize_session_features: bool = False,
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
    for frame in (train_df, val_df, test_df):
        add_protocol_invariant_features(frame, sanitize_session_features=sanitize_session_features)
    feat_cols = _get_feature_cols(train_df, sanitize_session_features=sanitize_session_features)
    if not feat_cols:
        raise ValueError("No numeric feature columns remain after session-feature sanitization")

    X_train_raw = train_df[feat_cols].to_numpy(dtype=np.float32, copy=True)
    X_val_raw   = val_df[feat_cols].to_numpy(dtype=np.float32, copy=True)
    X_test_raw  = test_df[feat_cols].to_numpy(dtype=np.float32, copy=True)

    log1p_columns = fit_log1p_columns(X_train_raw) if log1p else np.zeros(X_train_raw.shape[1], dtype=bool)
    X_train_raw = apply_log1p_columns(X_train_raw, log1p_columns)
    X_val_raw = apply_log1p_columns(X_val_raw, log1p_columns)
    X_test_raw = apply_log1p_columns(X_test_raw, log1p_columns)

    # Fit scaler on train only
    scaler = StandardScaler()
    X_train = _fit_transform_scaler_in_chunks(scaler, X_train_raw)
    X_val   = _transform_scaler_in_chunks(scaler, X_val_raw)
    X_test  = _transform_scaler_in_chunks(scaler, X_test_raw)

    # Fit numeric scaling on train only. In session-disjoint mode the complete
    # label vocabulary is known without using any held-out feature values.
    le = LabelEncoder()
    if label_classes is None:
        y_train = le.fit_transform(train_df[LABEL_COL].values)
    else:
        le.fit(np.asarray(label_classes, dtype=str))
        y_train = le.transform(train_df[LABEL_COL].values)
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
    split_mode: str = "stratified_random",
    sanitize_session_features: bool = False,
) -> dict:
    """
    Load, clean, split, scale — returns a dict with everything downstream needs.
    """
    if not 0 < sample <= 1:
        raise ValueError("sample must be in (0, 1]")
    df = load_all_cicids(force_reload=force_reload, sample=sample)
    data_hash = get_data_hash(df)

    # Downstream stages need split frames, and callers only use full_df for
    # label/provenance checks. Retain those columns instead of the full feature table.
    full_df = df[[LABEL_COL, "_source_file"]].copy()
    train_df, val_df, test_df = build_splits(df, seed=seed, split_mode=split_mode)
    del df
    gc.collect()

    # Build causal host context separately in each split so future/held-out rows
    # never contribute features to training rows.
    train_df = enrich_flow_with_host_context(train_df, HostWindowAggregator())
    val_df = enrich_flow_with_host_context(val_df, HostWindowAggregator())
    test_df = enrich_flow_with_host_context(test_df, HostWindowAggregator())

    (
        X_train, y_train,
        X_val,   y_val,
        X_test,  y_test,
        feat_cols,
        scaler,
        le,
        class_names,
    ) = get_feature_matrices(train_df, val_df, test_df, log1p=log1p,
                             sanitize_session_features=sanitize_session_features,
                             label_classes=(sorted(full_df[LABEL_COL].astype(str).unique())
                                            if split_mode == "session_disjoint" else None))

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
        "full_df":     full_df,
        "seed":        seed,
        "attack_families": ATTACK_FAMILIES,
        "label_map":       LABEL_MAP,
        "split_type": split_mode,
        "split_warning": ("Capture-session disjoint split; CICIDS source files are held wholly within one split."
                          if split_mode == "session_disjoint" else
                          "No Timestamp column: stratified random split. Near-duplicate flows may leak between train and test; results are optimistic."),
        "row_counts": {"train": len(train_df), "validation": len(val_df), "test": len(test_df)},
        "log1p": log1p,
        "sanitize_session_features": sanitize_session_features,
    }


if __name__ == "__main__":
    p = build_full_pipeline()
    print(f"\ndata_hash = {p['data_hash']}")
    print(f"X_train  = {p['X_train'].shape}")
    print(f"X_val    = {p['X_val'].shape}")
    print(f"X_test   = {p['X_test'].shape}")

