"""Prepare a small, stratified held-out CICIDS sample for in-process replay."""
from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.preprocessing import cicids_pipeline  # noqa: E402

LABEL_COL = cicids_pipeline.LABEL_COL
build_full_pipeline = cicids_pipeline.build_full_pipeline

NETWORK_METADATA_COLUMNS = {
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp",
}
CICIDS_DAY_BASES = {
    "Monday": datetime(2017, 7, 3, 8),
    "Tuesday": datetime(2017, 7, 4, 8),
    "Wednesday": datetime(2017, 7, 5, 8),
    "Thursday": datetime(2017, 7, 6, 8),
    "Friday": datetime(2017, 7, 7, 8),
}

DEFAULT_OUTPUT = BACKEND_DIR / "datasets" / "replay" / "replay_sample.csv.gz"


def _feature_columns(columns: list[str]) -> list[str]:
    """Return model numeric features, excluding traffic metadata in either source format."""
    metadata = {name.casefold() for name in NETWORK_METADATA_COLUMNS}
    return [name for name in columns if name.casefold() not in metadata]


def _file_base_timestamp(source_file: str) -> datetime:
    day = next((name for name in CICIDS_DAY_BASES if source_file.startswith(name)), None)
    if day is None:
        raise ValueError(f"Cannot determine a deterministic CICIDS day for {source_file!r}")
    base = CICIDS_DAY_BASES[day]
    if "Afternoon" in source_file:
        return base.replace(hour=12)
    return base


def _synthetic_value(source_file: str, row_index: int, field: str) -> bytes:
    seed = f"cicids-replay-v1|{source_file}|{row_index}|{field}".encode("utf-8")
    return hashlib.sha256(seed).digest()


def _add_replay_metadata(selected):
    """Preserve source metadata and fill absent fields deterministically, without label use."""
    import pandas as pd

    result = selected.copy()
    if "_source_file" not in result.columns:
        raise ValueError("Replay rows must retain their _source_file provenance column")
    missing_columns = {
        column: column not in result.columns
        for column in (
            "Timestamp", "Flow ID", "Source IP", "Destination IP", "Source Port", "Protocol"
        )
    }

    for source_file, index_values in result.groupby("_source_file", sort=False).groups.items():
        positions = list(index_values)
        row_indexes = range(len(positions))
        base_time = _file_base_timestamp(str(source_file))
        if missing_columns["Timestamp"]:
            result.loc[positions, "Timestamp"] = [
                (base_time + timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S")
                for index in row_indexes
            ]
        if missing_columns["Flow ID"]:
            result.loc[positions, "Flow ID"] = [
                "synthetic-" + _synthetic_value(str(source_file), index, "flow-id").hex()[:24]
                for index in row_indexes
            ]
        if missing_columns["Source IP"]:
            result.loc[positions, "Source IP"] = [
                f"198.18.{_synthetic_value(str(source_file), index, 'source-ip')[0]}.{_synthetic_value(str(source_file), index, 'source-ip')[1]}"
                for index in row_indexes
            ]
        if missing_columns["Destination IP"]:
            result.loc[positions, "Destination IP"] = [
                f"198.19.{_synthetic_value(str(source_file), index, 'destination-ip')[0]}.{_synthetic_value(str(source_file), index, 'destination-ip')[1]}"
                for index in row_indexes
            ]
        if missing_columns["Source Port"]:
            result.loc[positions, "Source Port"] = [
                1024 + int.from_bytes(_synthetic_value(str(source_file), index, "source-port")[:2], "big") % 64512
                for index in row_indexes
            ]
        if missing_columns["Protocol"]:
            result.loc[positions, "Protocol"] = [
                _synthetic_value(str(source_file), index, "protocol")[0]
                for index in row_indexes
            ]
    return result


def make_sample(
    n: int = 3000,
    seed: int = 42,
    output: Path = DEFAULT_OUTPUT,
    input_dir: Path | None = None,
) -> Path:
    if n < 1:
        raise ValueError("n must be positive")
    # Prefer the organized local dataset directory when it contains the complete set.
    if input_dir is None:
        candidates = [BACKEND_DIR / "datasets" / "trafficlabelling", cicids_pipeline.DATASETS_DIR]
        input_dir = next(
            (path for path in candidates if all((path / name).is_file() for name in cicids_pipeline.CICIDS_FILES)),
            candidates[0],
        )

    # Use a temporary cache so running this utility cannot change the normal
    # training/evaluation caches or accidentally reuse a cache from another CSV layout.
    original_data_dir = cicids_pipeline.DATASETS_DIR
    original_cache_dir = cicids_pipeline.CACHE_DIR
    with tempfile.TemporaryDirectory(prefix="cicids-replay-cache-") as cache_root:
        try:
            cicids_pipeline.DATASETS_DIR = Path(input_dir)
            cicids_pipeline.CACHE_DIR = Path(cache_root)
            # This utility only prepares rows; it does not train or evaluate a model.
            pipeline = build_full_pipeline(seed=seed, sample=1.0, log1p=False)
        finally:
            cicids_pipeline.DATASETS_DIR = original_data_dir
            cicids_pipeline.CACHE_DIR = original_cache_dir
    test_df = pipeline["test_df"]
    features = _feature_columns(pipeline["feat_cols"])
    labels = test_df[LABEL_COL].astype(str)
    from sklearn.model_selection import train_test_split

    take = min(n, len(test_df))
    if take == len(test_df):
        selected = test_df.copy()
    else:
        selected, _ = train_test_split(
            test_df,
            train_size=take,
            random_state=seed,
            stratify=labels,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    selected = _add_replay_metadata(selected)
    sample = selected[features].copy()
    for column in ("Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"):
        if column in selected.columns:
            sample.insert(0, column, selected[column].to_numpy())
    sample.insert(0, "family", selected[LABEL_COL].astype(str).to_numpy())
    sample.to_csv(output, index=False, compression="gzip")
    print(f"Saved {len(sample)} stratified held-out rows to {output}")
    print(f"Family counts: {sample['family'].value_counts().sort_index().to_dict()}")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=3000, help="number of held-out rows to save")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--input-dir", type=Path, default=None, help="directory containing the eight CICIDS2017 CSVs")
    args = parser.parse_args()
    make_sample(args.n, args.seed, args.output, args.input_dir)


if __name__ == "__main__":
    main()
