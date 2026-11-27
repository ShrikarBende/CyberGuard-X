"""Cross-dataset and capture-day evaluation for canonical flow datasets.

This evaluation is explicit and offline. It reports only measured results and
does not download data or modify the existing CICIDS2017 evaluation pipeline.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ml.datasets.adapters import CSE_FEATURE_COLUMNS, CSECICIDS2018Adapter, summarize_cse_ingestion
from ml.preprocessing.cicids_pipeline import LABEL_COL, _get_feature_cols, add_protocol_invariant_features


def _prepare_pair(train: pd.DataFrame, test: pd.DataFrame):
    # Feature engineering only adds columns/drops the raw port on these working
    # views. Shallow copies share the large input blocks and avoid duplicating
    # multi-million-row frames before the compact float32 matrices are built.
    train, test = train.copy(deep=False), test.copy(deep=False)
    for frame in (train, test):
        if LABEL_COL not in frame:
            raise ValueError("Dataset is missing canonical Label values")
        add_protocol_invariant_features(frame, sanitize_session_features=True)
    train_labels = set(train[LABEL_COL].astype(str))
    test_labels = set(test[LABEL_COL].astype(str))
    classes = sorted(train_labels & test_labels)
    if "BENIGN" not in classes or len(classes) < 2:
        raise ValueError("Evaluation requires BENIGN and at least one shared attack family")
    excluded = {
        "train_rows": int((~train[LABEL_COL].astype(str).isin(classes)).sum()),
        "test_rows": int((~test[LABEL_COL].astype(str).isin(classes)).sum()),
        "train_labels": sorted(train_labels - set(classes)),
        "test_labels": sorted(test_labels - set(classes)),
    }
    train_labels_all = train[LABEL_COL].astype(str)
    test_labels_all = test[LABEL_COL].astype(str)
    train_mask = train_labels_all.isin(classes).to_numpy()
    test_mask = test_labels_all.isin(classes).to_numpy()
    features = [c for c in _get_feature_cols(train, sanitize_session_features=True)
                if c in test.columns and pd.api.types.is_numeric_dtype(train[c])
                and pd.api.types.is_numeric_dtype(test[c])]
    if not features:
        raise ValueError("Datasets have no common numeric canonical flow features")
    def compact_matrix(frame: pd.DataFrame, row_mask: np.ndarray) -> np.ndarray:
        # Avoid pandas' wide row-and-column reindex temporary, which can exceed
        # local memory limits for multi-million-row CICIDS frames. Convert one
        # selected feature at a time directly into the final compact matrix.
        row_indices = np.flatnonzero(row_mask)
        matrix = np.empty((len(row_indices), len(features)), dtype=np.float32)
        for column_index, column in enumerate(features):
            values = frame[column].to_numpy(dtype=np.float32, copy=False)
            matrix[:, column_index] = values[row_indices]
        return matrix

    x_train = compact_matrix(train, train_mask)
    x_test = compact_matrix(test, test_mask)
    if not np.isfinite(x_train).all() or not np.isfinite(x_test).all():
        raise ValueError("Canonical feature matrices contain non-finite values")
    encoder = {name: index for index, name in enumerate(classes)}
    y_train = train_labels_all.loc[train_mask].map(encoder).to_numpy(dtype=np.int64)
    y_test = test_labels_all.loc[test_mask].map(encoder).to_numpy(dtype=np.int64)
    return x_train, y_train, x_test, y_test, features, classes, excluded


def evaluate_frames(train: pd.DataFrame, test: pd.DataFrame, *, seed: int = 42,
                    model_factory: Callable | None = None,
                    include_predictions: bool = False) -> dict:
    """Fit the existing LightGBM classifier on source data and score target data.

    A stratified source-only validation partition is used for LightGBM early
    stopping. The target remains held out; prediction uses the classifier's
    default argmax decision, with no target-set threshold selection.
    """
    x_train, y_train, x_test, y_test, features, classes, excluded = _prepare_pair(train, test)
    counts = np.bincount(y_train, minlength=len(classes))
    if np.any(counts < 2):
        raise ValueError("Each evaluated source class needs at least two rows for a source validation split")
    fit_idx, val_idx = train_test_split(
        np.arange(len(y_train)), test_size=0.2, random_state=seed, stratify=y_train,
    )
    scaler = StandardScaler().fit(x_train[fit_idx])
    x_fit = scaler.transform(x_train[fit_idx])
    x_val = scaler.transform(x_train[val_idx])
    x_target = scaler.transform(x_test)
    if model_factory is None:
        from ml.evaluation.known_classifier import train_lightgbm
        model = train_lightgbm(x_fit, y_train[fit_idx], x_val, y_train[val_idx], classes, seed=seed)
    else:
        model = model_factory(x_fit, y_train[fit_idx], x_val, y_train[val_idx], classes, seed)
    predictions = np.asarray(model.predict(x_target), dtype=np.int64)
    report = classification_report(y_test, predictions, labels=list(range(len(classes))),
                                   target_names=classes, output_dict=True, zero_division=0)
    result = {
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "per_family": {name: {"precision": float(report[name]["precision"]),
                               "recall": float(report[name]["recall"]),
                               "f1": float(report[name]["f1-score"]),
                               "support": int(report[name]["support"])} for name in classes},
        "classes": classes, "features": features, "excluded": excluded,
        "train_rows": int(len(y_train)), "test_rows": int(len(y_test)),
    }
    if include_predictions:
        result["_predicted_labels"] = [classes[int(index)] for index in predictions]
    return result


def cross_dataset_evaluation(cicids2017: pd.DataFrame, cse2018: pd.DataFrame, *, seed: int = 42,
                             model_factory: Callable | None = None) -> dict:
    """Run both CICIDS2017→2018 and 2018→CICIDS2017 directions."""
    result = {
        "protocol": "cross-dataset, train CICIDS2017 test CSE-CIC-IDS2018 (and reverse)",
        "seed": int(seed),
        "directions": {
            "CICIDS2017_to_CSE-CIC-IDS2018": evaluate_frames(cicids2017, cse2018, seed=seed,
                                                              model_factory=model_factory),
            "CSE-CIC-IDS2018_to_CICIDS2017": evaluate_frames(cse2018, cicids2017, seed=seed,
                                                              model_factory=model_factory),
        },
    }
    if cse2018.attrs.get("cse_ingestion"):
        result["cse_ingestion"] = cse2018.attrs["cse_ingestion"]
    if cicids2017.attrs.get("cicids_ingestion"):
        result["cicids_ingestion"] = cicids2017.attrs["cicids_ingestion"]
    return result


def cse_capture_day_evaluation(adapter: CSECICIDS2018Adapter | None = None, *, seed: int = 42,
                               model_factory: Callable | None = None) -> dict:
    """Binary attack-vs-benign leave-one-capture-day-out; family recalls are descriptive."""
    adapter = adapter or CSECICIDS2018Adapter()
    inventory: dict[str, dict[str, object]] = {}
    frames_by_day: dict[str, list[pd.DataFrame]] = {}
    ingestion_records = []
    for path in adapter.capture_files():
        frame = adapter.load_capture(path)
        metadata = frame.attrs["cse_ingestion"]
        ingestion_records.append(metadata)
        day = str(metadata["capture_day"])
        row = inventory.setdefault(day, {"files": [], "flows": 0, "families": {}, "family_files": {}})
        row["files"].append(path.name)
        row["flows"] += int(len(frame))
        counts = frame["Label"].value_counts().to_dict()
        for family, count in counts.items():
            row["families"][family] = row["families"].get(family, 0) + int(count)
            row["family_files"].setdefault(family, []).append(path.name)
        if day != "unknown":
            frames_by_day.setdefault(day, []).append(frame)
    days = sorted(day for day in inventory if day != "unknown")
    if len(days) < 2:
        raise ValueError("Multi-capture CSE evaluation needs at least two date-identifiable capture days")
    expected_families = ("Bot", "WebAttack", "BruteForce", "DosDDoS", "Infiltration", "PortScan")
    family_capture_counts = {}
    for family in expected_families:
        family_days = [day for day, stats in inventory.items()
                       if day != "unknown" and int(stats["families"].get(family, 0)) > 0]
        family_capture_counts[family] = {
            "capture_days": family_days,
            "n_capture_days": len(family_days),
            "n_files": sum(len(inventory[day]["family_files"].get(family, [])) for day in family_days),
            "flow_count": sum(int(inventory[day]["families"].get(family, 0)) for day in family_days),
        }
    folds = []
    for held_out in days:
        train = pd.concat([f for day, items in frames_by_day.items() if day != held_out for f in items], ignore_index=True)
        test = pd.concat(frames_by_day[held_out], ignore_index=True)
        original_test_labels = test["Label"].astype(str).to_numpy()
        train_binary, test_binary = train.copy(), test.copy()
        train_binary["Label"] = np.where(train_binary["Label"].astype(str) == "BENIGN", "BENIGN", "Attack")
        test_binary["Label"] = np.where(test_binary["Label"].astype(str) == "BENIGN", "BENIGN", "Attack")
        fold = evaluate_frames(
            train_binary, test_binary, seed=seed, model_factory=model_factory, include_predictions=True,
        )
        predicted_labels = fold.pop("_predicted_labels")
        predicted_labels = np.asarray(predicted_labels, dtype=object)
        fold_family_recall = {}
        for family in expected_families:
            family_mask = original_test_labels == family
            support = int(family_mask.sum())
            if support:
                fold_family_recall[family] = {
                    "recall": float(np.mean(predicted_labels[family_mask] == "Attack")),
                    "support": support,
                }
        folds.append({"held_out_capture_day": held_out,
                      **fold,
                      "per_family_recall_descriptive": fold_family_recall})
    per_family = {}
    for family in expected_families:
        supported = [fold["per_family_recall_descriptive"][family]
                     for fold in folds if family in fold["per_family_recall_descriptive"]]
        per_family[family] = {
            "mean_recall_descriptive": float(np.mean([row["recall"] for row in supported])) if supported else None,
            "n_capture_days_with_test_support": len(supported),
            "support": sum(int(row["support"]) for row in supported),
        }
    macro_f1s = [float(fold["macro_f1"]) for fold in folds]
    return {
        "protocol": "CSE-CIC-IDS2018 binary attack-vs-benign leave-one-capture-day-out",
        "n_capture_days": len(days), "capture_days": days, "seed": int(seed),
        "cse_ingestion": summarize_cse_ingestion(
            ingestion_records,
            max_rows_per_capture=adapter.max_rows_per_capture,
            sampling_seed=adapter.sampling_seed,
        ),
        "family_capture_counts": family_capture_counts,
        "aggregate": {
            "mean_capture_day_macro_f1": float(np.mean(macro_f1s)),
            "std_capture_day_macro_f1": float(np.std(macro_f1s)),
            "macro_f1_unit": "capture day; unweighted mean of held-out-day macro-F1",
            "per_family_recall": per_family,
        },
        "folds": folds,
    }


def load_cicids2017(*, max_rows_per_label: int = 50_000, seed: int = 42) -> pd.DataFrame:
    """Read the cleaned cache in batches and retain a deterministic label-stratified sample."""
    import pyarrow.parquet as parquet
    from ml.preprocessing.cicids_pipeline import _combined_cache_paths, load_all_cicids

    if max_rows_per_label < 1:
        raise ValueError("max_rows_per_label must be positive")
    cache_path, _ = _combined_cache_paths("full", 1.0)
    if not cache_path.exists():
        # This follows the established loader and reports its normal actionable
        # missing-source error if neither raw files nor the cache are available.
        load_all_cicids()
    parquet_file = parquet.ParquetFile(cache_path)
    reservoirs: dict[str, pd.DataFrame] = {}
    source_counts: dict[str, int] = {}
    for batch in parquet_file.iter_batches(batch_size=50_000, use_threads=False):
        chunk = batch.to_pandas()
        if LABEL_COL not in chunk:
            raise ValueError("CICIDS2017 cache is missing its canonical Label column")
        labels = chunk[LABEL_COL].astype(str)
        priorities = pd.util.hash_pandas_object(chunk, index=False).to_numpy(dtype=np.uint64)
        ordinals = np.arange(len(chunk), dtype=np.uint64)
        chunk = chunk.copy()
        chunk["_evaluation_priority"] = priorities ^ (ordinals + np.uint64(seed))
        for label, group in chunk.groupby(labels, sort=False):
            label = str(label)
            source_counts[label] = source_counts.get(label, 0) + len(group)
            existing = reservoirs.get(label)
            candidates = pd.concat([existing, group], ignore_index=True) if existing is not None else group
            if len(candidates) > max_rows_per_label:
                candidates = candidates.nsmallest(max_rows_per_label, "_evaluation_priority")
            reservoirs[label] = candidates
        del chunk
    result = pd.concat(reservoirs.values(), ignore_index=True).drop(columns="_evaluation_priority")
    result.attrs["cicids_ingestion"] = {
        "method": "deterministic feature-hash priority sample, stratified by Label",
        "seed": int(seed),
        "max_rows_per_label": int(max_rows_per_label),
        "source_rows": int(sum(source_counts.values())),
        "source_label_counts": source_counts,
        "retained_label_counts": {str(k): int(v) for k, v in result[LABEL_COL].value_counts().items()},
        "retained_rows": int(len(result)),
    }
    return result


def _transfer_feature_columns(cicids_schema: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Return common transfer features and the source columns needed to derive them."""
    cse_columns = list(dict.fromkeys(CSE_FEATURE_COLUMNS.values()))
    cse_schema = pd.DataFrame({column: pd.Series(dtype=np.float32) for column in cse_columns})
    cse_schema[LABEL_COL] = pd.Series(dtype=object)
    cicids_schema = cicids_schema.iloc[:0].copy()
    for frame in (cicids_schema, cse_schema):
        add_protocol_invariant_features(frame, sanitize_session_features=True)
    cicids_features = _get_feature_cols(cicids_schema, sanitize_session_features=True)
    cse_features = _get_feature_cols(cse_schema, sanitize_session_features=True)
    common_features = [column for column in cse_features if column in cicids_features]
    required_sources = {
        "Flow IAT Mean", "Flow IAT Std", "Total Length of Fwd Packets",
        "Total Length of Bwd Packets", "Destination Port",
    }
    source_columns = list(dict.fromkeys(
        [LABEL_COL, *[column for column in common_features if column not in {"iat_cv", "fwd_bwd_byte_ratio",
                                                                            "is_well_known_port", "is_registered_port",
                                                                            "is_ephemeral_port"}],
         *sorted(required_sources)]
    ))
    return common_features, source_columns


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("cross-dataset", "cse-capture-day"), required=True)
    parser.add_argument("--cse-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    adapter = CSECICIDS2018Adapter(root=args.cse_dir) if args.cse_dir else CSECICIDS2018Adapter()
    if args.mode == "cross-dataset":
        cicids2017 = load_cicids2017()
        _, transfer_columns = _transfer_feature_columns(cicids2017)
        # Trim both in-memory datasets to common transfer inputs before building
        # the matrices; raw per-day inputs remain untouched on disk.
        keep = set(transfer_columns)
        cicids2017.drop(columns=[column for column in cicids2017.columns if column not in keep],
                         inplace=True, errors="ignore")
        cse2018 = adapter.load_all(keep_columns=transfer_columns)
        result = cross_dataset_evaluation(cicids2017, cse2018, seed=args.seed)
    else:
        result = cse_capture_day_evaluation(adapter, seed=args.seed)
    rendered = json.dumps(result, indent=2, allow_nan=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
