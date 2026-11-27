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

from ml.datasets.adapters import CSECICIDS2018Adapter
from ml.preprocessing.cicids_pipeline import LABEL_COL, _get_feature_cols, add_protocol_invariant_features


def _prepare_pair(train: pd.DataFrame, test: pd.DataFrame):
    train, test = train.copy(), test.copy()
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
    train = train[train[LABEL_COL].astype(str).isin(classes)]
    test = test[test[LABEL_COL].astype(str).isin(classes)]
    features = [c for c in _get_feature_cols(train, sanitize_session_features=True)
                if c in test.columns and pd.api.types.is_numeric_dtype(train[c])
                and pd.api.types.is_numeric_dtype(test[c])]
    if not features:
        raise ValueError("Datasets have no common numeric canonical flow features")
    x_train = train[features].to_numpy(dtype=np.float32)
    x_test = test[features].to_numpy(dtype=np.float32)
    if not np.isfinite(x_train).all() or not np.isfinite(x_test).all():
        raise ValueError("Canonical feature matrices contain non-finite values")
    encoder = {name: index for index, name in enumerate(classes)}
    y_train = train[LABEL_COL].astype(str).map(encoder).to_numpy(dtype=np.int64)
    y_test = test[LABEL_COL].astype(str).map(encoder).to_numpy(dtype=np.int64)
    return x_train, y_train, x_test, y_test, features, classes, excluded


def evaluate_frames(train: pd.DataFrame, test: pd.DataFrame, *, seed: int = 42,
                    model_factory: Callable | None = None) -> dict:
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
    return {
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "per_family": {name: {"precision": float(report[name]["precision"]),
                               "recall": float(report[name]["recall"]),
                               "f1": float(report[name]["f1-score"]),
                               "support": int(report[name]["support"])} for name in classes},
        "classes": classes, "features": features, "excluded": excluded,
        "train_rows": int(len(y_train)), "test_rows": int(len(y_test)),
    }


def cross_dataset_evaluation(cicids2017: pd.DataFrame, cse2018: pd.DataFrame, *, seed: int = 42,
                             model_factory: Callable | None = None) -> dict:
    """Run both CICIDS2017→2018 and 2018→CICIDS2017 directions."""
    return {
        "protocol": "cross-dataset, train CICIDS2017 test CSE-CIC-IDS2018 (and reverse)",
        "seed": int(seed),
        "directions": {
            "CICIDS2017_to_CSE-CIC-IDS2018": evaluate_frames(cicids2017, cse2018, seed=seed,
                                                              model_factory=model_factory),
            "CSE-CIC-IDS2018_to_CICIDS2017": evaluate_frames(cse2018, cicids2017, seed=seed,
                                                              model_factory=model_factory),
        },
    }


def cse_capture_day_evaluation(adapter: CSECICIDS2018Adapter | None = None, *, seed: int = 42,
                               model_factory: Callable | None = None) -> dict:
    """Leave one filename-derived capture day out; files from one day stay grouped."""
    adapter = adapter or CSECICIDS2018Adapter()
    inventory = adapter.capture_inventory()
    days = sorted(day for day in inventory if day != "unknown")
    if len(days) < 2:
        raise ValueError("Multi-capture CSE evaluation needs at least two date-identifiable capture days")
    frames_by_day: dict[str, list[pd.DataFrame]] = {day: [] for day in days}
    for path in adapter.capture_files():
        frame = adapter.load_capture(path)
        day = str(frame["_capture_day"].iloc[0]) if len(frame) else "unknown"
        if day in frames_by_day:
            frames_by_day[day].append(frame)
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
        folds.append({"held_out_capture_day": held_out,
                      **evaluate_frames(train, test, seed=seed, model_factory=model_factory)})
    per_family = {}
    for family in expected_families:
        recalls = [fold["per_family"][family]["recall"] for fold in folds
                   if family in fold["per_family"] and fold["per_family"][family]["support"] > 0]
        per_family[family] = {
            "mean_recall_descriptive": float(np.mean(recalls)) if recalls else None,
            "n_capture_days_with_test_support": len(recalls),
        }
    macro_f1s = [float(fold["macro_f1"]) for fold in folds]
    return {
        "protocol": "CSE-CIC-IDS2018 leave-one-capture-day-out",
        "n_capture_days": len(days), "capture_days": days, "seed": int(seed),
        "family_capture_counts": family_capture_counts,
        "aggregate": {
            "mean_capture_day_macro_f1": float(np.mean(macro_f1s)),
            "std_capture_day_macro_f1": float(np.std(macro_f1s)),
            "macro_f1_unit": "capture day; unweighted mean of held-out-day macro-F1",
            "per_family_recall": per_family,
        },
        "folds": folds,
    }


def load_cicids2017() -> pd.DataFrame:
    """Load the locally placed CICIDS2017 source files through the existing cleaner."""
    from ml.preprocessing.cicids_pipeline import load_all_cicids
    return load_all_cicids()


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
        result = cross_dataset_evaluation(load_cicids2017(), adapter.load_all(), seed=args.seed)
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
