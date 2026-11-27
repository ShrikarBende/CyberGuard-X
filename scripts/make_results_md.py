"""Generate docs/RESULTS.md exclusively from JSON files listed in FINAL.json."""
from __future__ import annotations

import json
import hashlib
import statistics
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "backend" / "ml" / "evaluation" / "results"
OUTPUT = ROOT / "docs" / "RESULTS.md"
AGENT_OUTPUT = ROOT / "docs" / "agent" / "RESULTS.md"
SEEDS = (42, 43, 44)


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        f"Model: `{result['model_name']}`; date: `{result['date_utc']}`; seed: `{result['seed']}`; sample size: {result['sample_size']}; used FakeLLM: `{str(bool(result.get('used_fake_llm', True))).lower()}`.",
        f"Inputs: {result['source_counts'].get('held_out_cicids_replay', 0)} held-out CICIDS replay rows and {result['synthetic_demo_sample_count']} synthetic demo rows. Demo-derived values are synthetic.",
        "FakeLLM scripted evaluation validates plumbing only. It does not measure real-model quality or support an improvement claim.", "",
        "| Arm | Valid citation rate before validator | Unsupported technique rate | ATT&CK precision (expected classes) | ATT&CK recall (expected classes) | Mean steps | Mean tool calls | Mean latency seconds | Fallback rate | Limit reached rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, row in (("Deterministic baseline", baseline), ("Agent (FakeLLM)", agent)):
        lines.append("| " + name + " | " + " | ".join(_metric(row.get(key)) for key in (
            "valid_citation_rate_before_validator", "unsupported_technique_rate",
            "attack_mapping_precision_macro_expected_classes", "attack_mapping_recall_macro_expected_classes",
            "mean_steps", "mean_tool_calls", "mean_latency_seconds", "fallback_rate", "limit_reached_rate")) + " |")
    lines += ["", f"Injection guard suite: {injection['passed_count']}/{injection['payload_count']} passed with FakeLLM; scope is scripted guard verification only.",
              f"Regression suite F1–F5: {'passed' if result.get('regression_suite', {}).get('all_passed') else 'failed'}; {result.get('regression_suite', {}).get('scope', 'not recorded').rstrip('.')}.",
              "Expected ATT&CK techniques are versioned in `backend/ml/evaluation/expected_techniques.json`; precision and recall include only listed classes.", ""]
    return "\n".join(lines)


def update_agent_section(result: dict) -> Path:
    section = render_agent_section(result)
    AGENT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    AGENT_OUTPUT.write_text("# Agent investigation results\n\n" + section + "\n", encoding="utf-8")
    return AGENT_OUTPUT


def _metric_cell(family: dict, name: str) -> str:
    metric = family.get("metrics", {}).get(name, {})
    mean, interval = metric.get("mean"), metric.get("95CI_across_seeds", [None, None])
    if mean is None or not interval or interval[0] is None or interval[1] is None:
        return "n/a"
    return f"{float(mean):.4f} ({float(interval[0]):.4f}–{float(interval[1]):.4f})"


def render_network_baseline(artifact_path: Path) -> str:
    """Render every network-baseline metric from one complete saved JSON artifact."""
    artifact_path = artifact_path.resolve()
    results_root = RESULTS.resolve()
    if results_root not in artifact_path.parents or artifact_path.suffix.lower() != ".json":
        raise ValueError("Network baseline artifact must be a JSON file under backend/ml/evaluation/results")
    payload = read(artifact_path)
    if payload.get("run_status") != "complete" or payload.get("artifact_schema_version") != 1:
        raise ValueError("Refusing to render an incomplete or unsupported network baseline artifact")
    required = ("dataset", "holdout", "split_rules", "seeds", "families", "model_and_decision_policy")
    if any(key not in payload for key in required):
        raise ValueError("Network baseline artifact is missing required provenance")
    expected_families = {"DosDDoS", "PortScan", "BruteForce", "WebAttack", "Bot"}
    if {row.get("family") for row in payload["families"]} != expected_families:
        raise ValueError("Network baseline artifact does not contain every expected family")
    dataset = payload["dataset"]
    holdout = payload["holdout"]
    model = payload["model_and_decision_policy"]
    relative_artifact = Path("../backend/ml/evaluation/results") / artifact_path.name
    lines = [
        "# Network evaluation results", "",
        "This report is generated from one saved network-baseline JSON artifact. It does not run model evaluation.", "",
        f"Artifact: [`{artifact_path.name}`]({relative_artifact.as_posix()}) (run `{payload['run_id']}`).",
        f"Dataset: `{dataset['version']}`; raw source-file SHA-256 fingerprint: `{dataset['sha256']}`; processed development sample SHA-256: `{dataset['processed_development_sample_sha256']}`.",
        f"Frozen holdout: `{', '.join(holdout['source_sessions'])}`; manifest SHA-256: `{holdout['manifest_sha256']}`; status: {holdout['status']}.",
        f"Session split: {payload['split_rules']['session_unit']}. {payload['split_rules']['development_test']}. {payload['split_rules']['development_validation']}.",
        f"Seeds: `{', '.join(str(seed) for seed in payload['seeds'])}`. Development sampling: {dataset['sample_method']}.",
        f"Decision policy: {model['classifier']}; {model['detector']}; threshold is the {model['threshold']}.",
        f"Confidence intervals: {model['bootstrap']['across_seeds']} ({model['bootstrap']['across_seed_resamples']:,} resamples). Each seed’s interval uses {model['bootstrap']['per_seed']} ({model['bootstrap']['per_seed_resamples']:,} resamples).", "",
        "## Per-family unknown-review metrics", "",
        "Values are the mean across seed runs with the 95% bootstrap interval across those seed-level estimates. The unknown class is the named family in the row; other test labels are treated as known only when that class was present in training.", "",
        "| Attack family | Test sessions | Unknown support by seed | Precision | Recall | F1 | Known FPR | Benign replay false-alert rate |",
        "|---|---|---|---:|---:|---:|---:|---:|",
    ]
    for family in payload["families"]:
        supports = "; ".join(
            f"{row['seed']}: {row['support']['unknown_positive']}" for row in family["seed_runs"]
        )
        sessions = ", ".join(f"`{name}`" for name in family["test_source_sessions"])
        lines.append(
            f"| {family['family']} | {sessions} | {supports} | "
            f"{_metric_cell(family, 'precision')} | {_metric_cell(family, 'recall')} | "
            f"{_metric_cell(family, 'f1')} | {_metric_cell(family, 'fpr')} | "
            f"{_metric_cell(family, 'benign_replay_false_alert_rate')} |"
        )
    lines += [
        "", "## Interpretation and split audit", "",
        f"{payload['split_integrity']}. The final holdout was excluded from row loading, model fitting, threshold selection, and scoring; only raw file checksums were read to verify the frozen dataset identity.",
        f"The benign replay false-alert rate is measured on BENIGN rows in the development test capture sessions: {payload['metric_definitions']['benign_replay_false_alert_rate']}.",
        f"Unknown review semantics: {payload['metric_definitions']['unknown_review_semantics']}.",
        "The bootstrap interval resamples the five seed-level estimates on fixed development test sessions. It reflects seed variability, not uncertainty across a large sample of independent capture sessions.",
        "CICIDS2017 source files contain no timestamps. Host-window features therefore remain zero in this baseline, and the final holdout consists of one complete source-file session.",
        "Per-seed supports, session assignments, thresholds, excluded unseen test labels, and row-bootstrap intervals are recorded in the linked JSON artifact.", "",
    ]
    return "\n".join(lines)


def latest_network_baseline() -> Path:
    candidates = sorted(RESULTS.glob("network_baseline_*.json"), reverse=True)
    for path in candidates:
        try:
            if read(path).get("run_status") == "complete":
                return path
        except (OSError, json.JSONDecodeError):
            continue
    raise FileNotFoundError("No complete network_baseline_*.json artifact exists; run scripts/run_network_eval.py first")


def host_window_ablation_section() -> list[str]:
    """Render the latest saved paired ablation status and baseline comparison."""
    candidates = sorted(RESULTS.glob("ablation_host_window_*.json"), reverse=True)
    if not candidates:
        return []
    ablation_path = candidates[0]
    ablation = read(ablation_path)
    baseline_path = RESULTS / ablation["baseline_artifact"]
    if not baseline_path.is_file() or sha256_file(baseline_path) != ablation["baseline_artifact_sha256"]:
        raise RuntimeError("Host-window ablation references a missing or changed frozen baseline artifact")
    baseline = read(baseline_path)
    families = {row["family"]: row for row in baseline["families"]}
    baseline_values = {
        "Bot recall": _metric_cell(families["Bot"], "recall"),
        "PortScan recall": _metric_cell(families["PortScan"], "recall"),
        "Bot precision": _metric_cell(families["Bot"], "precision"),
        "PortScan precision": _metric_cell(families["PortScan"], "precision"),
        "Bot F1": _metric_cell(families["Bot"], "f1"),
        "PortScan F1": _metric_cell(families["PortScan"], "f1"),
        "Macro unknown-review F1": f"{statistics.mean(row['metrics']['f1']['mean'] for row in baseline['families']):.4f}",
        "Macro open-set rejection (recall)": f"{statistics.mean(row['metrics']['recall']['mean'] for row in baseline['families']):.4f}",
        "Macro benign replay false-alert rate": f"{statistics.mean(row['metrics']['benign_replay_false_alert_rate']['mean'] for row in baseline['families']):.4f}",
    }
    lines = [
        "", "## Controlled ablation 1: host-window features", "",
        f"Ablation artifact: [`{ablation_path.name}`](../backend/ml/evaluation/results/{ablation_path.name}).",
        f"Status: **{ablation['status']}**. The final holdout remains untouched; comparison is pinned to `{baseline_path.name}` with the same seeds and split rules.",
        "", "| Metric | Frozen baseline | Host-window ablation | Delta |", "|---|---:|---:|---:|",
    ]
    for metric, value in baseline_values.items():
        lines.append(f"| {metric} | {value} | n/a | n/a |")
    if ablation.get("status") == "not_evaluable":
        missing = sorted({field for item in ablation.get("development_header_findings", [])
                          for field in item.get("missing_required_window_fields", [])})
        lines += [
            "", f"**Why no delta is reported:** {ablation['reason']}",
            f"Required fields absent from development session headers: `{', '.join(missing) or 'development files unavailable'}`. No model was fitted for this ablation.",
            "A valid rerun requires flow telemetry containing per-row timestamps and source-host identifiers. Do not infer timestamps from row order or derive a 60-second window from aggregate flow IAT fields.",
        ]
    return lines


def branch_fusion_ablation_section() -> list[str]:
    """Render the latest saved branch/fusion feasibility and provenance artifact."""
    candidates = sorted(RESULTS.glob("branch_fusion_ablation_*.json"), reverse=True)
    if not candidates:
        return []
    artifact_path = candidates[0]
    artifact = read(artifact_path)
    protected = artifact["protected_artifacts"]
    holdout_path = ROOT / "backend" / "ml" / "evaluation" / "holdout_manifest.json"
    network_path = RESULTS / "network_baseline_20261127T093255Z.json"
    if (sha256_file(holdout_path) != protected["holdout_manifest_sha256"] or
            sha256_file(network_path) != protected["network_baseline_sha256"]):
        raise RuntimeError("Protected holdout or network baseline changed since branch/fusion feasibility record")
    sources = artifact["data_provenance"]
    lines = [
        "", "## Controlled ablation 2: standalone branches versus calibrated fusion", "",
        f"Feasibility artifact: [`{artifact_path.name}`](../backend/ml/evaluation/results/{artifact_path.name}).",
        f"Status: **{artifact['status']}**. Required multi-seed metrics are not available because the branch data do not form a shared entity-disjoint labeled cohort.",
        "", "| Branch | Available data and label provenance | Entity-disjoint standalone metrics |", "|---|---|---|",
        f"| Endpoint (Autoencoder + iForest) | {sources['endpoint_autoencoder_iforest']['training_source_available']} | Not evaluable: {sources['endpoint_autoencoder_iforest']['label_scope']} |",
        f"| User/Sequence (TFT) | {sources['user_sequence_tft']['training_source_available']}; {sources['user_sequence_tft']['label_source']} | Not evaluated here: {sources['user_sequence_tft']['label_scope']} |",
        f"| Host-Graph (GAT) | {sources['host_graph_gat']['training_source_available']}; labels use `{sources['host_graph_gat']['label_source']}` | Not evaluated here: {sources['host_graph_gat']['label_scope']} |",
        f"| Calibrated Fusion Meta-Classifier | `{sources['calibrated_fusion_meta_classifier']['fallback_training_source']}`; {sources['calibrated_fusion_meta_classifier']['label_scope']} | Not comparable: {sources['calibrated_fusion_meta_classifier']['split_scope']} |",
        "", "| Comparison metric | Strongest standalone branch | Fusion on same held-out entities | Delta |", "|---|---:|---:|---:|",
        "| Precision / Recall / F1 / AUPRC / FPR | n/a | n/a | n/a |",
        "", "No fusion-improvement claim is made. Endpoint captures, user sequences, UNSW graph flows and Fusion training labels come from distinct cohorts and targets; the existing saved metrics cannot be paired into one test set. Synthetic fallback results are not real captured-log performance, and heuristic or attack-category proxy labels are not independent incident ground truth.",
        "", "The holdout manifest and frozen network baseline were hashed for integrity verification only; they were not modified, used for training, or scored.",
        "", "A valid rerun requires one independently labeled multi-modal cohort with aligned user, device, and capture/scenario identifiers. Split those entities into train, calibration, and test groups first; generate out-of-fold branch scores for training entities; fit/calibrate Fusion on training groups only; then compare each standalone branch and Fusion on the exact same untouched test entities.",
    ]
    return lines


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-only", action="store_true", help="update only the generated agent evaluation section from the latest agent_eval JSON")
    parser.add_argument("--legacy-open-set", action="store_true", help="regenerate the historical FINAL.json report instead of the frozen-holdout baseline")
    parser.add_argument("--network-baseline", type=Path, help="render a specific saved network baseline JSON artifact")
    args = parser.parse_args()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if args.agent_only:
        agent_files = sorted(RESULTS.glob("agent_eval_*.json"))
        if not agent_files:
            raise SystemExit("No agent_eval_*.json result exists")
        result = read(agent_files[-1])
        print(f"Updated generated agent section in {update_agent_section(result)} from {agent_files[-1]}")
    elif args.legacy_open_set:
        OUTPUT.write_text(render(), encoding="utf-8")
        print(f"Wrote historical report to {OUTPUT}")
    else:
        artifact = args.network_baseline or latest_network_baseline()
        report = render_network_baseline(artifact)
        report += "\n".join(host_window_ablation_section())
        report += "\n".join(branch_fusion_ablation_section())
        OUTPUT.write_text(report, encoding="utf-8")
        print(f"Wrote {OUTPUT} from saved artifact {artifact}")
