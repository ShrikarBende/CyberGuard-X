"""Compare standard and capture-session-disjoint CICIDS medium evaluation."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.evaluation.open_set_pipeline import RESULTS_DIR, evaluate_one_family
from ml.preprocessing.cicids_pipeline import build_full_pipeline


def _ci(values: list[float]) -> list[float | None]:
    if not values:
        return [None, None]
    mean = float(np.mean(values))
    sem = float(np.std(values, ddof=1) / np.sqrt(len(values))) if len(values) > 1 else 0.0
    return [max(0.0, mean - 1.96 * sem), min(1.0, mean + 1.96 * sem)]


def run_comparison(seeds: tuple[int, ...] = (42, 43), sample: float = .5) -> dict:
    records = []
    skipped = []
    all_families = None
    for mode in ("stratified_random", "session_disjoint"):
        for seed in seeds:
            pipeline = build_full_pipeline(seed=seed, sample=sample, log1p=True, split_mode=mode,
                                           sanitize_session_features=(mode == "session_disjoint"))
            pipeline.update({"train_row_cap_per_fold": 60_000, "bootstrap_resamples": 200,
                             "classifier_estimators": 80,
                             "detectors": ["confidence"],
                             "run_id": f"medium_{mode}_seed{seed}"})
            all_families = list(pipeline["attack_families"])
            for family in pipeline["attack_families"]:
                result = evaluate_one_family(family, pipeline)
                if result.get("skipped"):
                    skipped.append({"split_mode": mode, "seed": seed, "family": family,
                                    "reason": result["skipped"]})
                    continue
                detector = result["detectors"]["confidence"]
                records.append({"split_mode": mode, "seed": seed, "family": family,
                    "OSCR_AUC": detector["oscr_auc"], "Unknown_Recall": detector["unknown_recall"],
                    "Benign_FPR": detector.get("benign_false_positive_rate"),
                    "Known_Macro_F1": detector["known_macro_f1"],
                    "unknown_support": result["n_test_unknown"],
                    "known_support": result["n_test_known"]})
    metrics = ("OSCR_AUC", "Unknown_Recall", "Benign_FPR", "Known_Macro_F1")
    summary = {}
    for mode in ("stratified_random", "session_disjoint"):
        subset = [row for row in records if row["split_mode"] == mode]
        summary[mode] = {metric: {"mean": (float(np.mean(vals)) if vals else None),
            "95CI": _ci(vals)} for metric in metrics
            for vals in [[float(row[metric]) for row in subset if row.get(metric) is not None]]}
    payload = {"pipeline_stage": "session_disjoint_comparison", "profile": "medium",
        "sample_fraction": sample, "train_row_cap_per_fold": 60_000,
        "classifier_estimators": 80, "seeds": list(seeds), "detector": "confidence",
        "label_provenance": "CICIDS2017 dataset labels; reported as dataset-labeled metrics, not independently verified incident ground truth",
        "split_definitions": {"stratified_random": "per-source-file stratified row split",
            "session_disjoint": "GroupShuffleSplit over source_file plus contiguous 12-hour Timestamp block, or source_file when Timestamp is absent"},
        "records": records, "skipped_folds": skipped,
        "expected_folds_per_split_mode": len(seeds) * len(all_families or []), "summary": summary}
    output = RESULTS_DIR / "medium_stratified_vs_session_disjoint.json"
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md = ["# Medium CICIDS2017: stratified vs session-disjoint", "",
          "Dataset labels are used for these metrics; they are not independently verified incident ground truth.", "",
          "| Split | OSCR AUC | Unknown Recall | Benign FPR | Known Macro F1 |", "|---|---:|---:|---:|---:|"]
    for mode, vals in summary.items():
        def fmt(metric: str) -> str:
            item = vals[metric]
            return "n/a" if item["mean"] is None else f"{item['mean']:.4f} ({item['95CI'][0]:.4f}–{item['95CI'][1]:.4f})"
        md.append(f"| {mode} | {fmt('OSCR_AUC')} | {fmt('Unknown_Recall')} | {fmt('Benign_FPR')} | {fmt('Known_Macro_F1')} |")
    md.extend(["", f"Seeds: {', '.join(map(str, seeds))}. Confidence intervals use the standard error across available seed/family folds."])
    if skipped:
        md.append(f"Session grouping left {sum(row['split_mode'] == 'session_disjoint' for row in skipped)} family/seed folds without held-out unknown support; those folds are omitted and listed in the JSON report.")
    markdown = RESULTS_DIR / "medium_stratified_vs_session_disjoint.md"
    markdown.write_text("\n".join(md) + "\n", encoding="utf-8")
    payload["markdown_report_path"] = str(markdown)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


if __name__ == "__main__":
    result = run_comparison()
    print(f"Saved session-disjoint comparison: {result['markdown_report_path']}")
