"""Summarize held-out CICIDS test rows through the live, side-effect-free scorer."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import joblib
BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.detection.engine import predict_flow  # noqa: E402
from app.core.config import settings  # noqa: E402
from ml.preprocessing.cicids_pipeline import LABEL_COL, build_full_pipeline  # noqa: E402

ARTIFACT_PATH = Path(settings.MODEL_BUNDLE_PATH)
RESULTS_DIR = BACKEND_DIR / "ml" / "evaluation" / "results"
LOW_SUPPORT_THRESHOLD = 200
WILSON_Z = 1.959963984540054


def wilson_interval(successes: int, total: int, z: float = WILSON_Z) -> dict:
    """Return a two-sided Wilson score interval for a binomial proportion."""
    if total <= 0:
        return {"lower": None, "upper": None}
    p = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    radius = z * ((p * (1 - p) / total + z2 / (4 * total * total)) ** 0.5) / denominator
    return {"lower": max(0.0, center - radius), "upper": min(1.0, center + radius)}


def stratified_sample(frame, n: int, seed: int):
    """Sample approximately proportionally by family, guaranteeing representation."""
    n = min(n, len(frame))
    groups = [(label, group) for label, group in frame.groupby(LABEL_COL, sort=True)]
    if n < len(groups):
        raise ValueError(f"n={n} is too small to include all {len(groups)} test families")
    exact = {label: n * len(group) / len(frame) for label, group in groups}
    allocation = {label: min(len(group), max(1, int(exact[label]))) for label, group in groups}
    while sum(allocation.values()) < n:
        candidates = [label for label, group in groups if allocation[label] < len(group)]
        if not candidates:
            break
        label = max(candidates, key=lambda value: (exact[value] - allocation[value], len(dict(groups)[value])))
        allocation[label] += 1
    while sum(allocation.values()) > n:
        candidates = [label for label, _ in groups if allocation[label] > 1]
        if not candidates:
            break
        label = max(candidates, key=lambda value: (allocation[value] - exact[value], allocation[value]))
        allocation[label] -= 1
    parts = [group.sample(n=allocation[label], random_state=seed) for label, group in groups]
    import pandas as pd

    return pd.concat(parts).sample(frac=1, random_state=seed)


def replay_metadata(bundle: dict, pipeline: dict, row_count: int, seed: int) -> dict:
    """Describe the saved replay sample and the model/pipeline used to score it."""
    profile = bundle.get("profile", bundle.get("profile_name"))
    if isinstance(profile, dict):
        profile = profile.get("name")
    return {
        "model_version": bundle.get("model_version", "not recorded"),
        "profile": profile or "not recorded",
        "n_replayed": row_count,
        "split_type": pipeline.get("split_type", "not recorded"),
        "seed": seed,
        "sampling_method": "sampled stratified by family",
    }


def create_summary(n: int = 5000, seed: int = 42) -> dict:
    if n < 1:
        raise ValueError("N must be positive")
    if not ARTIFACT_PATH.is_file():
        raise FileNotFoundError(
            f"Configured CICIDS model bundle was not found: {ARTIFACT_PATH}. "
            "Set MODEL_BUNDLE_PATH to an existing bundle; no alternate bundle is loaded."
        )
    bundle = joblib.load(ARTIFACT_PATH)
    pipeline = build_full_pipeline(seed=seed, sample=0.15, log1p=True)
    test_rows = pipeline["test_df"]
    selected = stratified_sample(test_rows, n, seed)
    confusion_counts: Counter = Counter()
    verdict_counts: Counter = Counter()
    family_totals: Counter = Counter()
    family_stats: dict[str, dict[str, int]] = {}
    features = bundle["feature_names"]
    for _, row in selected.iterrows():
        truth = str(row[LABEL_COL])
        flow = {name: float(row[name]) for name in features}
        prediction = predict_flow(flow, bundle)
        verdict = prediction["verdict"]
        predicted = prediction["predicted_class"]
        family_totals[truth] += 1
        verdict_counts[(truth, verdict)] += 1
        if truth not in family_stats:
            family_stats[truth] = {"alerted": 0, "correct": 0}
        family_stats[truth]["alerted"] += verdict != "BENIGN"
        family_stats[truth]["correct"] += (
            verdict == "BENIGN" and truth == "BENIGN" and predicted == truth
        ) or (verdict == "KNOWN_THREAT" and truth != "BENIGN" and predicted == truth)
        matrix_column = "UNKNOWN_CANDIDATE" if verdict == "UNKNOWN_CANDIDATE" else predicted
        confusion_counts[(truth, matrix_column)] += 1

    families = sorted(family_totals)
    predicted_columns = list(bundle["class_names"]) + ["UNKNOWN_CANDIDATE"]
    matrix = {
        "rows": families,
        "columns": predicted_columns,
        "counts": [
            [confusion_counts[(family, column)] for column in predicted_columns]
            for family in families
        ],
    }
    family_metrics = {}
    for family in families:
        support = family_totals[family]
        alerted = family_stats[family]["alerted"]
        correct = family_stats[family]["correct"]
        family_metrics[family] = {
            "support": support,
            "support_label": "low support" if support < LOW_SUPPORT_THRESHOLD else None,
            "alerted_rate": alerted / support,
            "alerted_rate_95_wilson": wilson_interval(alerted, support),
            "correct_class_recall": correct / support,
            "correct_class_recall_95_wilson": wilson_interval(correct, support),
        }
    benign_total = family_totals.get("BENIGN", 0)
    benign_unknown = confusion_counts[("BENIGN", "UNKNOWN_CANDIDATE")]
    return {
        **replay_metadata(bundle, pipeline, len(selected), seed),
        "score_name": bundle["score_name"],
        "n_requested": n,
        "ground_truth_vs_verdict_counts": [
            {"ground_truth": family, "verdict": verdict, "count": count}
            for (family, verdict), count in sorted(verdict_counts.items())
        ],
        "predicted_class_confusion_matrix": matrix,
        "benign_unknown_candidate_fraction": benign_unknown / benign_total if benign_total else None,
        "per_family_metrics": family_metrics,
        "warnings": [
            "Replay summary is descriptive only; no thresholds or model settings were tuned from it.",
            pipeline.get("split_warning", "").strip(),
        ] if pipeline.get("split_warning") else [
            "Replay summary is descriptive only; no thresholds or model settings were tuned from it."
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", "--n", "--rows", dest="rows", type=int, default=5000,
                        help="Held-out test rows to replay, stratified by family")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    summary = create_summary(args.rows, args.seed)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RESULTS_DIR / f"replay_{date.today().isoformat()}.json"
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    matrix = summary["predicted_class_confusion_matrix"]
    print("Predicted-class confusion matrix (rows=ground truth, columns=predicted class/verdict)")
    print("ground_truth | " + " | ".join(matrix["columns"]))
    print("-------------|" + "|".join(["---"] * len(matrix["columns"])))
    for family, values in zip(matrix["rows"], matrix["counts"]):
        print(f"{family} | " + " | ".join(str(value) for value in values))
    print(f"BENIGN flagged UNKNOWN_CANDIDATE fraction: {summary['benign_unknown_candidate_fraction']}")
    print("Per-family metrics (rates with 95% Wilson intervals):")
    for family, metrics in summary["per_family_metrics"].items():
        low_support = f" [{metrics['support_label']}]" if metrics["support_label"] else ""
        alert_ci = metrics["alerted_rate_95_wilson"]
        recall_ci = metrics["correct_class_recall_95_wilson"]
        print(f"  {family}: support={metrics['support']}{low_support}; "
              f"alerted={metrics['alerted_rate']:.4f} "
              f"(95% CI {alert_ci['lower']:.4f}-{alert_ci['upper']:.4f}); "
              f"correct-class recall={metrics['correct_class_recall']:.4f} "
              f"(95% CI {recall_ci['lower']:.4f}-{recall_ci['upper']:.4f})")
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
