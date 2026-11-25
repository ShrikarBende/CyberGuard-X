"""Generate docs/RESULTS.md exclusively from JSON files listed in FINAL.json."""
from __future__ import annotations

import json
import statistics
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "backend" / "ml" / "evaluation" / "results"
OUTPUT = ROOT / "docs" / "RESULTS.md"
SEEDS = (42, 43, 44)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def mean_sd(values) -> str:
    values = [float(value) for value in values]
    return f"{statistics.mean(values):.4f} ± {statistics.stdev(values):.4f}"


def manifest_entries() -> tuple[dict, list[dict]]:
    manifest = read(RESULTS / "FINAL.json")
    entries = manifest.get("results")
    if not isinstance(entries, list):
        raise RuntimeError("FINAL.json must contain a results list")
    for entry in entries:
        filename = Path(entry.get("file", ""))
        if (filename.suffix.lower() != ".json" or filename.is_absolute() or
                any(part in {"", ".", ".."} for part in filename.parts) or
                len(filename.parts) > 2 or (len(filename.parts) == 2 and filename.parts[0] != "archive")):
            raise RuntimeError(f"Invalid result filename in FINAL.json: {entry.get('file')!r}")
    return manifest, entries


def listed_files(entries: list[dict], kind: str) -> list[tuple[dict, dict]]:
    return [(entry, read(RESULTS / entry["file"])) for entry in entries if entry.get("kind") == kind]


def family_map(run: dict) -> dict:
    return {row["family"]: row for row in run.get("per_family", [])}


def markdown_separator(alignments: tuple[str, ...]) -> str:
    """Build one separator cell per declared table column."""
    tokens = {"left": "---", "center": ":---:", "right": "---:"}
    if any(alignment not in tokens for alignment in alignments):
        raise ValueError("Unknown Markdown table alignment")
    return "|" + "|".join(tokens[alignment] for alignment in alignments) + "|"


def render() -> str:
    manifest, entries = manifest_entries()
    open_rows = listed_files(entries, "open_set")
    open_runs = [data for _entry, data in open_rows if data.get("profile_name") == "medium"]
    open_runs.sort(key=lambda run: int(run["seed"]))
    if [int(run["seed"]) for run in open_runs] != list(SEEDS):
        raise RuntimeError("FINAL.json must list medium open-set runs for seeds 42, 43, and 44")
    light_rows = [(entry, data) for entry, data in open_rows
                  if entry.get("role") == "sample_size_sensitivity" and
                  data.get("profile_name") == "light" and int(data.get("seed", -1)) == 42]
    medium42 = [run for run in open_runs if int(run["seed"]) == 42]
    if len(light_rows) != 1 or len(medium42) != 1:
        raise RuntimeError("FINAL.json must list exactly one light and medium seed-42 open-set run")
    known_rows = listed_files(entries, "known_classifier")
    known_rows = [(entry, data) for entry, data in known_rows
                  if data.get("profile_name") == "medium" and int(data.get("seed", -1)) in SEEDS]
    known_rows.sort(key=lambda row: int(row[1]["seed"]))
    if [int(data["seed"]) for _, data in known_rows] != list(SEEDS):
        raise RuntimeError("FINAL.json must list known-classifier medium runs for seeds 42, 43, and 44")
    replay_rows = listed_files(entries, "replay")
    rag_rows = listed_files(entries, "rag_retrieval")
    if len(replay_rows) != 1 or len(rag_rows) != 1:
        raise RuntimeError("FINAL.json must list exactly one replay and RAG report")
    replay, rag = replay_rows[0][1], rag_rows[0][1]

    families = {}
    for run in open_runs:
        seed = int(run["seed"])
        for row in run.get("per_family", []):
            fam = row["family"]
            families.setdefault(fam, {"support": {}, "detectors": {}})
            families[fam]["support"][seed] = {
                "n": int(row["n_test_unknown"]),
                "label": str(row.get("unknown_support", "")).lower().replace("_", " "),
            }
            for detector, values in row.get("detectors", {}).items():
                families[fam]["detectors"].setdefault(detector, {})[seed] = values

    lines = [
        "# Evaluation results", "",
        "Generated only from saved JSON files listed in `backend/ml/evaluation/results/FINAL.json`; this report does not run evaluation.", "",
        "## Medium open-set results", "",
        "AUROC and unknown rejection are mean ± sample standard deviation over saved medium seeds.", "",
        "| Family | Detector | AUROC mean ± sd | Unknown rejection mean ± sd | Unknown test rows by seed | Low support |",
        "|---|---|---:|---:|---|---|",
    ]
    for fam, values in sorted(families.items()):
        support = values["support"]
        count_text = "; ".join(f"{seed}: {support[seed]['n']}" for seed in SEEDS)
        unknown_counts = [support[seed]["n"] for seed in SEEDS]
        if any(count < 200 for count in unknown_counts):
            support_label = "Low support"
        elif any(200 <= count <= 300 for count in unknown_counts):
            support_label = "Borderline support"
        else:
            support_label = "No"
        for detector, per_seed in sorted(values["detectors"].items()):
            rows = [per_seed[seed] for seed in SEEDS]
            lines.append(f"| {fam} | {detector} | {mean_sd([r['AUROC'] for r in rows])} | "
                         f"{mean_sd([r['unknown_rejection_rate'] for r in rows])} | {count_text} | {support_label} |")

    report_facts = manifest.get("report_facts", {})
    percentiles_by_detector = {}
    for run in open_runs:
        for family in run.get("per_family", []):
            for detector, metric in family.get("detectors", {}).items():
                if "threshold_percentile" in metric:
                    percentiles_by_detector.setdefault(detector, set()).add(float(metric["threshold_percentile"]))
    union_percentiles = percentiles_by_detector.get("union_conf_mahalanobis", set())
    other_percentiles = {
        value for detector, values in percentiles_by_detector.items()
        if detector != "union_conf_mahalanobis" for value in values
    }
    if len(union_percentiles) != 1 or len(other_percentiles) != 1:
        raise RuntimeError("Saved open-set JSONs do not contain one consistent percentile for union and other detectors")
    union_percentile = next(iter(union_percentiles))
    other_percentile = next(iter(other_percentiles))
    medium_fraction_for_seed = float(medium42[0]["sample_fraction"])
    lines += ["",
              f"`union_conf_mahalanobis` uses the {union_percentile:g}th percentile of each component; every other detector uses the {other_percentile:g}th percentile of known validation scores.",
              f"The {medium_fraction_for_seed:.0%} sample is selected by feature-row hash and is identical across seeds; the seed changes the stratified per-source train/validation/test split and seeded model randomness.",
              "", "### How to read the open-set tables", "",
              f"With {len(open_runs)} seeds, detectors whose mean ± sd ranges overlap are not ranked. Bootstrap intervals, where shown, reflect test-sampling noise only.", ""]

    # Sample-size sensitivity compares common detector outputs in matched seed-42 runs.
    light = family_map(light_rows[0][1])
    med = family_map(medium42[0])
    light_metadata = light_rows[0][1]
    medium_metadata = medium42[0]
    light_fraction = float(light_metadata["sample_fraction"])
    medium_fraction = float(medium_metadata["sample_fraction"])
    light_cap = int(light_metadata["train_row_cap_per_fold"])
    medium_cap = int(medium_metadata["train_row_cap_per_fold"])
    detector_names = ("confidence", "isolation_forest", "mahalanobis", "confidence_mahalanobis_rank_average")
    lines += ["## Sample-size sensitivity", "",
              "AUROC and unknown rejection are shown side by side for the light and medium seed-42 runs.", "",
              "| Family | Detector | Light AUROC | Medium AUROC | Light unknown rejection | Medium unknown rejection |",
              "|---|---|---:|---:|---:|---:|"]
    for fam in sorted(set(light) & set(med)):
        for detector in detector_names:
            if detector not in light[fam].get("detectors", {}) or detector not in med[fam].get("detectors", {}):
                continue
            lval, mval = light[fam]["detectors"][detector], med[fam]["detectors"][detector]
            lines.append(f"| {fam} | {detector} | {float(lval['AUROC']):.4f} | {float(mval['AUROC']):.4f} | "
                         f"{float(lval['unknown_rejection_rate']):.4f} | {float(mval['unknown_rejection_rate']):.4f} |")
    lines += ["",
              f"Confidence-based AUROC differed strongly between the light ({light_fraction:.0%} sample, {light_cap:,}-row cap) and medium ({medium_fraction:.0%}, {medium_cap:,}-row cap) profiles on DosDDoS and PortScan; anomaly detectors changed little. The cause was not isolated.", ""]

    replay_profile = replay.get("profile")
    if isinstance(replay_profile, dict):
        replay_profile = replay_profile.get("name")
    replay_metadata = {
        "model_version": replay.get("model_version"),
        "profile": replay_profile,
        "rows": replay.get("n_replayed"),
        "split_type": replay.get("split_type"),
        "seed": replay.get("seed"),
        "sampling_method": replay.get("sampling_method"),
    }
    replay_metadata = {key: ("not recorded" if value in (None, "") else value)
                       for key, value in replay_metadata.items()}
    matrix = replay["predicted_class_confusion_matrix"]
    lines += ["## Replay summary", "",
              "Replay metadata: " + "; ".join(f"{key}={value}" for key, value in replay_metadata.items()) + ".", "",
              "### Confusion matrix", "",
              "| Ground truth / verdict | " + " | ".join(matrix["columns"]) + " |",
              "|---|" + "---:|" * len(matrix["columns"])]
    for name, row in zip(matrix["rows"], matrix["counts"]):
        lines.append(f"| {name} | " + " | ".join(str(value) for value in row) + " |")
    replay_family_alignments = ("left", "right", "left", "right", "right")
    lines += ["", "### Per-family replay metrics", "",
              "| Family | Support | Low support | Alerted / false-alert rate | Correct-class recall / specificity |",
              markdown_separator(replay_family_alignments)]
    for fam, metric in replay["per_family_metrics"].items():
        low = str(metric.get("support_label", "")).lower() == "low support"
        if fam == "BENIGN":
            alerted_text = f"false-alert rate: {float(metric['alerted_rate']):.4f}"
            recall_text = f"specificity: {float(metric['correct_class_recall']):.4f}"
        else:
            alerted_text = f"alerted rate: {float(metric['alerted_rate']):.4f}"
            recall_text = f"correct-class recall: {float(metric['correct_class_recall']):.4f}"
        lines.append(f"| {fam} | {metric['support']} | {'Yes' if low else 'No'} | {alerted_text} | {recall_text} |")

    lines += ["", "## RAG retrieval", "", "20 developer-written questions, indicative only.", "",
              f"- Questions: {rag['question_count']}", f"- Model: `{rag['model_name']}`",
              f"- FAISS backend: `{rag['faiss_backend']}`", f"- Knowledge-file hash: `{rag['knowledge_file_hash']}`",
              f"- Hit@1: {float(rag['hit_at_1']):.4f}", f"- Hit@3: {float(rag['hit_at_3']):.4f}", "",
              "Missed questions and top retrieved source:", ""]
    for item in rag.get("missed_questions", []):
        lines.append(f"- {item['question']} — expected `{item['expected_source_file']}`, top source `{item.get('top_retrieved_source') or 'none'}`.")
    if not rag.get("missed_questions"):
        lines.append("- None recorded.")

    model_names = sorted({name for _, run in known_rows for name, value in run.items()
                          if isinstance(value, dict) and "macro_f1" in value})
    lines += ["", "## Known-class classifier metrics", "",
              "Mean ± sample standard deviation over the medium seeds.", "",
              "| Model | Macro-F1 mean ± sd | Accuracy mean ± sd |",
              "|---|---:|---:|"]
    for model in model_names:
        metrics = [run[model] for _, run in known_rows]
        lines.append(f"| {metrics[0].get('model', model)} | {mean_sd([x['macro_f1'] for x in metrics])} | {mean_sd([x['accuracy'] for x in metrics])} |")
    lines += ["", "### Per-class metrics", "",
              "| Model | Class | Precision mean ± sd | Recall mean ± sd | F1 mean ± sd | Support by seed |",
              "|---|---|---:|---:|---:|---|"]
    classes = sorted({cls for _, run in known_rows for model in model_names for cls in run[model].get("per_class", {})})
    class_f1_means = {}
    for model in model_names:
        for cls in classes:
            metrics = [run[model]["per_class"][cls] for _, run in known_rows]
            class_f1_means[(model, cls)] = statistics.mean(float(x["f1"]) for x in metrics)
            lines.append(f"| {model} | {cls} | {mean_sd([x['precision'] for x in metrics])} | "
                         f"{mean_sd([x['recall'] for x in metrics])} | {mean_sd([x['f1'] for x in metrics])} | "
                         + "; ".join(f"{run['seed']}: {run[model]['per_class'][cls]['support']}" for _, run in known_rows) + " |")
    lowest_model, lowest_class = min(class_f1_means, key=class_f1_means.get)
    lowest_class_mean = class_f1_means[(lowest_model, lowest_class)]
    lines += [f"", f"Lowest-F1 known class from these results: {lowest_class} ({lowest_model}).", "",
              "Accuracy is shown last in the summary table because benign flows dominate the test set.", ""]

    limits = report_facts.get("limitations", {})
    medium_bot = med.get("Bot", {}).get("n_test_unknown", 0)
    medium_web = med.get("WebAttack", {}).get("n_test_unknown", 0)
    portscan_rates = {}
    for fam, values in families.items():
        detector_names_for_family = values["detectors"]
        portscan_rates[fam] = max(
            float(per_seed[seed]["unknown_rejection_rate"])
            for per_seed in detector_names_for_family.values()
            for seed in SEEDS
        )
    max_portscan_rejection = portscan_rates["PortScan"]
    weakest_family = min(portscan_rates, key=portscan_rates.get)
    if weakest_family != "PortScan":
        raise RuntimeError("Saved medium results do not support PortScan as weakest by maximum unknown rejection")
    threshold_percentile = next(
        int(metric["threshold_percentile"])
        for row in open_runs[0]["per_family"]
        for metric in row["detectors"].values()
        if "threshold_percentile" in metric
    )
    known_false_reject_target = 1 - threshold_percentile / 100
    lines += ["", "## Metric definitions", "",
        "- AUROC: how well the detector score ranks held-out unknown rows above known rows.",
        f"- Unknown rejection: the fraction of held-out unknown rows rejected at the {known_false_reject_target:.0%} known false-reject threshold selected using known validation data.",
        "- Alerted rate: the fraction of replay rows that produced an alert.",
        "- Correct-class recall: the fraction of rows in a family assigned that correct family verdict.",
        "", "## Limitations", "",
        f"- stratified random split with no timestamps (near-duplicate flows can sit in both train and test, so results are optimistic)",
        f"- single dataset, CICIDS{limits.get('dataset_year')}, from a {limits.get('dataset_year')} testbed with known labelling problems",
        f"- {report_facts.get('sample_fractions', {}).get('light') * 100:g}% and {report_facts.get('sample_fractions', {}).get('medium') * 100:g}% hash samples",
        f"- {len(SEEDS)} seeds only",
        f"- Bot ({medium_bot} rows) and WebAttack ({medium_web} rows) have few unknown test rows",
        f"- PortScan is the weakest family for open-set rejection; the maximum observed unknown rejection across its detectors and seeds was {max_portscan_rejection:.4f}",
        f"- {lowest_class} is the weakest known class (mean F1 {lowest_class_mean:.4f})",
        f"- replay families with under {limits.get('replay_low_support_flows')} flows are not interpretable",
        f"- the RAG test is {rag['question_count']} developer-written questions",
        "- correlation scenarios and thresholds are developer-written demo values",
        "- the user and endpoint layers have no trained model",
        "- TFT and GAT are not implemented",
        ""]
    return "\n".join(lines)


AGENT_START = "<!-- GENERATED AGENT EVALUATION: START -->"
AGENT_END = "<!-- GENERATED AGENT EVALUATION: END -->"


def _metric(value):
    return "n/a" if value is None else f"{float(value):.4f}"


def render_agent_section(result: dict) -> str:
    metrics = result["metrics"]
    baseline = metrics["baseline"]
    agent = metrics["agent"]
    injection = result["injection_suite"]
    lines = [
        "## Agent investigation evaluation (generated)", "",
        f"Model: `{result['model_name']}`; date: `{result['date_utc']}`; seed: `{result['seed']}`; sample size: {result['sample_size']}.",
        f"Inputs: {result['source_counts'].get('held_out_cicids_replay', 0)} held-out CICIDS replay rows and {result['synthetic_demo_sample_count']} synthetic demo rows. Demo-derived values are synthetic.",
        "FakeLLM scripted evaluation validates plumbing only. It does not measure real-model quality or support an improvement claim.", "",
        "| Arm | Valid citation rate before validator | Unsupported technique rate | ATT&CK precision (expected classes) | ATT&CK recall (expected classes) | Mean steps | Mean tool calls | Mean latency seconds | Fallback rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, row in (("Deterministic baseline", baseline), ("Agent (FakeLLM)", agent)):
        lines.append("| " + name + " | " + " | ".join(_metric(row.get(key)) for key in (
            "valid_citation_rate_before_validator", "unsupported_technique_rate",
            "attack_mapping_precision_macro_expected_classes", "attack_mapping_recall_macro_expected_classes",
            "mean_steps", "mean_tool_calls", "mean_latency_seconds", "fallback_rate")) + " |")
    lines += ["", f"Injection guard suite: {injection['passed_count']}/{injection['payload_count']} passed with FakeLLM; scope is scripted guard verification only.",
              "Expected ATT&CK techniques are versioned in `backend/ml/evaluation/expected_techniques.json`; precision and recall include only listed classes.", ""]
    return "\n".join(lines)


def update_agent_section(result: dict) -> Path:
    section = render_agent_section(result)
    existing = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else "# Evaluation results\n"
    block = f"{AGENT_START}\n{section}\n{AGENT_END}"
    if AGENT_START in existing and AGENT_END in existing:
        before, rest = existing.split(AGENT_START, 1)
        _old, after = rest.split(AGENT_END, 1)
        updated = before.rstrip() + "\n\n" + block + after
    else:
        marker = "<!-- GENERATED RESULTS: END -->"
        if marker in existing:
            before, after = existing.split(marker, 1)
            updated = before + marker + "\n\n" + block + after
        else:
            updated = existing.rstrip() + "\n\n" + block + "\n"
    OUTPUT.write_text(updated, encoding="utf-8")
    return OUTPUT


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-only", action="store_true", help="update only the generated agent evaluation section from the latest agent_eval JSON")
    args = parser.parse_args()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if args.agent_only:
        agent_files = sorted(RESULTS.glob("agent_eval_*.json"))
        if not agent_files:
            raise SystemExit("No agent_eval_*.json result exists")
        result = read(agent_files[-1])
        print(f"Updated generated agent section in {update_agent_section(result)} from {agent_files[-1]}")
    else:
        OUTPUT.write_text(render(), encoding="utf-8")
        print(f"Wrote {OUTPUT}")
        print("Read JSON files:")
        for entry in manifest_entries()[1]:
            print(f"- {entry['file']}")
