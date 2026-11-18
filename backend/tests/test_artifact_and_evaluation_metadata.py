"""Configured bundle, backend-relative SQLite, and evaluation JSON behavior."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import BACKEND_DIR as CONFIG_BACKEND_DIR, Settings, settings
from app.database.session import resolve_database_url
from app.detection import engine as detection_engine
from app.services import evaluation_results
from ml.models import registry


def test_model_bundle_path_defaults_to_medium_and_resolves_relative_values(tmp_path):
    default = Settings(_env_file=None, SECRET_KEY="test-key")
    assert Path(default.MODEL_BUNDLE_PATH) == (
        CONFIG_BACKEND_DIR / "saved_models" / "cicids2017_medium_lightgbm.bundle.pkl"
    )

    configured = Settings(
        _env_file=None,
        SECRET_KEY="test-key",
        MODEL_BUNDLE_PATH="saved_models/custom.bundle.pkl",
    )
    assert Path(configured.MODEL_BUNDLE_PATH) == (
        CONFIG_BACKEND_DIR / "saved_models" / "custom.bundle.pkl"
    )


def test_missing_configured_bundle_fails_with_path_and_no_fallback(tmp_path, monkeypatch):
    missing = tmp_path / "missing.bundle.pkl"
    monkeypatch.setattr(detection_engine, "MODEL_BUNDLE_PATH", missing)
    monkeypatch.setattr(detection_engine, "_MODEL_BUNDLE_CACHE", None)
    with pytest.raises(FileNotFoundError, match="no alternate bundle") as exc_info:
        detection_engine.load_model_bundle()
    assert str(missing) in str(exc_info.value)


def test_engine_and_model_registry_share_the_configured_bundle_path():
    configured = Path(settings.MODEL_BUNDLE_PATH)
    assert detection_engine.MODEL_BUNDLE_PATH == configured
    assert registry.MODEL_BUNDLE_PATH == configured
    status = registry.get_models_status()
    assert status["models"]["cicids2017_lightgbm"]["file"] == str(configured)


def test_relative_sqlite_paths_resolve_from_backend_directory(tmp_path, monkeypatch):
    relative = resolve_database_url("sqlite:///./cyberguardx.db")
    assert Path(relative.database) == (CONFIG_BACKEND_DIR / "cyberguardx.db").resolve()

    monkeypatch.chdir(tmp_path)
    still_relative_to_backend = resolve_database_url("sqlite:///./cyberguardx.db")
    assert Path(still_relative_to_backend.database) == (CONFIG_BACKEND_DIR / "cyberguardx.db").resolve()

    in_memory = resolve_database_url("sqlite:///:memory:")
    assert in_memory.database == ":memory:"


def test_results_directory_is_under_backend_ml_evaluation():
    assert evaluation_results.RESULTS_DIR == BACKEND_DIR / "ml" / "evaluation" / "results"


def test_env_example_documents_every_application_setting():
    env_example = BACKEND_DIR.parent / ".env.example"
    variables = {
        line.split("=", 1)[0].strip()
        for line in env_example.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }
    assert set(Settings.model_fields) <= variables
    gitignore = (BACKEND_DIR.parent / ".gitignore").read_text(encoding="utf-8")
    assert "*.db" in gitignore
    assert ".medium_seed43.log" in gitignore
    assert ".pytest_cache/" in gitignore


def _write_json(path: Path, data: dict, modified: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    if modified is not None:
        os.utime(path, (modified, modified))
    return path


def _run(run_id: str, seed: int, auroc: float, rejection: float, support: int = 250):
    return {
        "pipeline_stage": "open_set_evaluation",
        "run_id": run_id,
        "profile_name": "medium",
        "sample_fraction": 0.5,
        "train_row_cap_per_fold": 150000,
        "seed": seed,
        "date": f"2026-11-{seed - 21:02d}T00:00:00",
        "per_family": [{
            "family": "BruteForce",
            "n_test_unknown": support,
            "detectors": {
                "confidence": {
                    "AUROC": auroc,
                    "unknown_rejection_rate": rejection,
                    "threshold_percentile": 95,
                }
            },
        }],
    }


def _manifest(*entries: str) -> dict:
    return {"results": [{"file": name, "kind": "open_set"} for name in entries]}


def test_evaluation_results_list_runs_ignore_partials_and_select_newest(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation_results, "RESULTS_DIR", tmp_path)
    old = _write_json(tmp_path / "open_set_old.json", _run("old", 42, 0.8, 0.6), 100)
    newest = _write_json(tmp_path / "open_set_new.json", _run("new", 43, 0.9, 0.7), 200)
    _write_json(tmp_path / "partial_open_set_partial.json", _run("partial", 44, 0.1, 0.1), 300)
    _write_json(tmp_path / "open_set_x_progress.json", _run("progress", 45, 0.1, 0.1), 400)
    _write_json(tmp_path / "open_set_y_capture.json", _run("capture", 46, 0.1, 0.1), 500)
    _write_json(tmp_path / "scores" / "open_set_score.json", _run("score", 47, 0.1, 0.1), 600)
    _write_json(tmp_path / "known_classifier_new.json", {
        "pipeline_stage": "known_classifier", "profile_name": "medium",
        "sample_fraction": 0.5, "seed": 43,
    }, 210)
    _write_json(tmp_path / "FINAL.json", {
        "results": [
            {"file": "open_set_old.json", "kind": "open_set"},
            {"file": "open_set_new.json", "kind": "open_set"},
            {"file": "known_classifier_new.json", "kind": "known_classifier"},
        ]
    })

    runs = evaluation_results.list_evaluation_runs()
    assert [run["run_id"] for run in runs] == ["new", "old"]
    assert runs[0]["profile"] == "medium"
    assert runs[0]["sample_fraction"] == 0.5

    newest_result = evaluation_results.get_evaluation_result()
    assert newest_result["open_set"]["run_id"] == "new"
    assert newest_result["known_classifier"]["seed"] == 43
    assert newest_result["files"] == ["known_classifier_new.json", newest.name]

    selected = evaluation_results.get_evaluation_result("old")
    assert selected["open_set"]["run_id"] == "old"
    assert selected["files"] == [old.name]
    assert evaluation_results.get_evaluation_result("missing") is None


def test_evaluation_summary_aggregates_seed_metrics_and_low_support(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation_results, "RESULTS_DIR", tmp_path)
    _write_json(tmp_path / "open_set_seed42.json", _run("seed42", 42, 0.8, 0.6, support=199), 100)
    _write_json(tmp_path / "open_set_seed43.json", _run("seed43", 43, 0.9, 0.8, support=240), 200)
    _write_json(tmp_path / "open_set_full.json", {
        "run_id": "full42", "profile_name": "full", "seed": 42,
        "sample_fraction": 1.0, "per_family": [],
    }, 300)
    _write_json(tmp_path / "FINAL.json", _manifest("open_set_seed42.json", "open_set_seed43.json"))

    profiles = evaluation_results.build_evaluation_summary()
    assert [profile["profile"] for profile in profiles] == ["medium"]
    medium = profiles[0]
    assert medium["n_seeds"] == 2
    family = medium["families"][0]
    assert family["family"] == "BruteForce"
    assert family["n_seeds"] == 2
    assert family["low_support"] is True
    detector = family["detectors"]["confidence"]
    assert detector["n_seeds"] == 2
    assert detector["AUROC"]["mean"] == pytest.approx(0.85)
    assert detector["AUROC"]["std"] == pytest.approx(0.05)
    assert detector["unknown_rejection_rate"]["mean"] == pytest.approx(0.7)
    assert detector["unknown_rejection_rate"]["std"] == pytest.approx(0.1)


def test_evaluation_summary_ignores_non_manifest_and_lists_archive_only_on_request(tmp_path, monkeypatch):
    monkeypatch.setattr(evaluation_results, "RESULTS_DIR", tmp_path)
    _write_json(tmp_path / "open_set_final42.json", _run("final42", 42, 0.8, 0.6), 100)
    _write_json(tmp_path / "open_set_final43.json", _run("final43", 43, 0.9, 0.8), 200)
    archive = tmp_path / "archive"
    _write_json(archive / "open_set_archive42.json", _run("archive42", 42, 0.2, 0.1), 300)
    _write_json(archive / "open_set_archive43.json", _run("archive43", 43, 0.3, 0.2), 400)
    _write_json(tmp_path / "open_set_unlisted.json", _run("unlisted", 44, 0.1, 0.1), 500)
    _write_json(tmp_path / "FINAL.json", _manifest("open_set_final42.json", "open_set_final43.json"))

    standard = evaluation_results.build_evaluation_summary()
    assert [profile["profile"] for profile in standard] == ["medium"]
    assert standard[0]["n_seeds"] == 2
    with_archive = evaluation_results.build_evaluation_summary(include_archive=True)
    assert len(with_archive) == 1
    assert with_archive[0]["n_seeds"] == 2
    assert with_archive[0]["families"][0]["detectors"]["confidence"]["AUROC"]["mean"] == pytest.approx(0.25)


def test_results_markdown_uses_only_json_files_in_final_manifest(tmp_path, monkeypatch):
    import importlib.util

    script_path = BACKEND_DIR.parent / "scripts" / "make_results_md.py"
    spec = importlib.util.spec_from_file_location("make_results_md_under_test", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "RESULTS", tmp_path)

    entries = []
    for seed, auroc in ((42, 0.8), (43, 0.9), (44, 0.85)):
        name = f"open_set_seed{seed}.json"
        run = _run(f"seed{seed}", seed, auroc, 0.7)
        run["profile_name"] = "medium"
        for family, family_rejection in (("Bot", 0.2), ("DosDDoS", 0.8),
                                         ("PortScan", 0.1), ("WebAttack", 0.6)):
            run["per_family"].append({
                "family": family, "n_test_unknown": 250,
                "detectors": {"confidence": {
                    "AUROC": auroc, "unknown_rejection_rate": family_rejection,
                    "threshold_percentile": 95,
                }},
            })
        for family in run["per_family"]:
            family["detectors"]["union_conf_mahalanobis"] = {
                "AUROC": auroc,
                "unknown_rejection_rate": family["detectors"]["confidence"]["unknown_rejection_rate"],
                "threshold_percentile": 97.5,
            }
        _write_json(tmp_path / name, run)
        entries.append({"file": name, "kind": "open_set", "profile": "medium"})
    known_name = "known.json"
    _write_json(tmp_path / known_name, {
        "seed": 42, "profile_name": "medium", "LightGBM": {"model": "LightGBM", "macro_f1": 0.9, "accuracy": 0.95,
                                    "per_class": {"BENIGN": {"precision": 0.9, "recall": 0.9,
                                                               "f1": 0.9, "support": 10}}},
    })
    for seed in (43, 44):
        extra = {
            "seed": seed, "profile_name": "medium",
            "LightGBM": {"model": "LightGBM", "macro_f1": 0.9 + (seed - 42) / 100,
                         "accuracy": 0.95, "per_class": {"BENIGN": {"precision": 0.9,
                         "recall": 0.9, "f1": 0.9, "support": 10}}},
        }
        extra_name = f"known{seed}.json"
        _write_json(tmp_path / extra_name, extra)
        entries.append({"file": extra_name, "kind": "known_classifier"})
    entries.append({"file": known_name, "kind": "known_classifier"})
    replay_name = "replay.json"
    _write_json(tmp_path / replay_name, {
        "predicted_class_confusion_matrix": {"rows": ["BENIGN"], "columns": ["BENIGN"], "counts": [[10]]},
        "per_family_metrics": {"BENIGN": {"support": 10, "alerted_rate": 0.0, "correct_class_recall": 1.0}},
    })
    entries.append({"file": replay_name, "kind": "replay"})
    rag_name = "rag.json"
    _write_json(tmp_path / rag_name, {
        "question_count": 20, "model_name": "test-model", "faiss_backend": "faiss",
        "knowledge_file_hash": "abc", "hit_at_1": 0.8, "hit_at_3": 0.9, "missed_questions": [],
    })
    entries.append({"file": rag_name, "kind": "rag_retrieval"})
    _write_json(tmp_path / "open_set_unlisted.json", {
        **_run("unlisted", 45, 0.01, 0.02),
        "per_family": [{"family": "SHOULD_NOT_APPEAR", "n_test_unknown": 1,
                        "detectors": {"confidence": {"AUROC": 0.01, "unknown_rejection_rate": 0.02}}}],
    })
    light = _run("light", 42, 0.7, 0.6)
    light["profile_name"] = "light"
    light["sample_fraction"] = 0.15
    light["train_row_cap_per_fold"] = 60000
    for family, family_rejection in (("Bot", 0.2), ("DosDDoS", 0.8),
                                     ("PortScan", 0.1), ("WebAttack", 0.6)):
        light["per_family"].append({
            "family": family, "n_test_unknown": 250,
            "detectors": {"confidence": {
                "AUROC": 0.7, "unknown_rejection_rate": family_rejection,
                "threshold_percentile": 95,
            }},
        })
    _write_json(tmp_path / "light.json", light)
    entries.append({"file": "light.json", "kind": "open_set", "role": "sample_size_sensitivity"})
    _write_json(tmp_path / "FINAL.json", {"results": entries, "report_facts": {
        "sample_fractions": {"light": 0.15, "medium": 0.5},
        "open_set_reading": {"indistinguishable_sd": 2.5, "low_support_rows": 200,
                             "known_false_reject_rate": 0.05},
        "limitations": {"dataset_year": 2017, "replay_low_support_flows": 100},
    }})

    markdown = module.render()
    assert "BruteForce" in markdown
    assert "SHOULD_NOT_APPEAR" not in markdown
    assert "Sample-size sensitivity" in markdown
    assert "Macro-F1 mean ± sd" in markdown
    assert "Lowest-F1 known class from these results: BENIGN" in markdown
    assert "With 3 seeds, detectors whose mean ± sd ranges overlap are not ranked." in markdown
    assert "Metric definitions" in markdown
    assert "union_conf_mahalanobis` uses the 97.5th percentile of each component; every other detector uses the 95th percentile" in markdown


def test_generated_markdown_tables_have_consistent_column_counts():
    import importlib.util
    import re

    script_path = BACKEND_DIR.parent / "scripts" / "make_results_md.py"
    spec = importlib.util.spec_from_file_location("make_results_md_table_shape", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    lines = module.render().splitlines()
    index = 0
    table_number = 0
    while index < len(lines):
        if not (lines[index].startswith("|") and lines[index].endswith("|")):
            index += 1
            continue
        block = []
        while index < len(lines) and lines[index].startswith("|") and lines[index].endswith("|"):
            block.append(lines[index])
            index += 1
        table_number += 1
        cell_counts = [len(line[1:-1].split("|")) for line in block]
        assert len(block) >= 2, f"table {table_number} is missing its separator row"
        expected = cell_counts[0]
        assert cell_counts[1] == expected, f"table {table_number} header/separator widths differ: {cell_counts[:2]}"
        separator_cells = block[1][1:-1].split("|")
        assert all(re.fullmatch(r":?-{3,}:?", cell) for cell in separator_cells), (
            f"table {table_number} has an invalid separator row"
        )
        assert all(count == expected for count in cell_counts[2:]), (
            f"table {table_number} row widths differ: {cell_counts}"
        )
    assert table_number > 0


def test_report_reads_replay_fields_and_marks_missing_fields_as_not_recorded():
    import importlib.util

    script_path = BACKEND_DIR.parent / "scripts" / "make_results_md.py"
    spec = importlib.util.spec_from_file_location("make_results_md_replay_metadata", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    markdown = module.render()
    assert "Replay metadata: model_version=cicids2017-medium-v1; profile=not recorded; rows=20000; split_type=not recorded; seed=42; sampling_method=not recorded." in markdown
    assert "| BENIGN | 16589 | No | false-alert rate: 0.0310 | specificity: 0.9690 |" in markdown
    assert "| WebAttack | confidence | 0.9894 ± 0.0058 | 0.9599 ± 0.0134 | 42: 216; 43: 216; 44: 216 | Borderline support |" in markdown
    assert "Bootstrap intervals, where shown, reflect test-sampling noise only." in markdown
    assert "whether they have run in CI" not in markdown


def test_replay_summary_metadata_is_written_for_future_runs():
    from ml.training.replay_summary import replay_metadata

    actual = replay_metadata(
        {"model_version": "test-version", "profile": {"name": "medium"}},
        {"split_type": "stratified_random"},
        row_count=123,
        seed=42,
    )
    assert actual == {
        "model_version": "test-version",
        "profile": "medium",
        "n_replayed": 123,
        "split_type": "stratified_random",
        "seed": 42,
        "sampling_method": "sampled stratified by family",
    }


def test_results_table_values_have_listed_json_provenance():
    """Every numeric table cell is either read from FINAL-listed JSON or derived across its seeds."""
    import importlib.util
    import re
    import statistics

    script_path = BACKEND_DIR.parent / "scripts" / "make_results_md.py"
    spec = importlib.util.spec_from_file_location("make_results_md_provenance", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    manifest, entries = module.manifest_entries()
    markdown = module.render()
    raw = [json.loads((module.RESULTS / entry["file"]).read_text(encoding="utf-8")) for entry in entries]
    allowed = set()
    def collect(value):
        if isinstance(value, dict):
            for child in value.values(): collect(child)
        elif isinstance(value, list):
            for child in value: collect(child)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            allowed.add(str(value))
            allowed.add(f"{float(value):.4f}")
    for data in raw:
        collect(data)

    def add_derived(values):
        values = [float(value) for value in values]
        allowed.add(f"{statistics.mean(values):.4f}")
        allowed.add(f"{statistics.stdev(values):.4f}")

    open_runs = [d for d in raw if d.get("profile_name") == "medium" and "per_family" in d]
    known_runs = [d for d in raw if d.get("profile_name") == "medium" and "LightGBM" in d]
    for family in open_runs[0]["per_family"]:
        fam = family["family"]
        for detector in family["detectors"]:
            for metric in ("AUROC", "unknown_rejection_rate"):
                add_derived([next(x for x in run["per_family"] if x["family"] == fam)["detectors"][detector][metric]
                             for run in open_runs])
    for metric in ("macro_f1", "accuracy"):
        add_derived([run["LightGBM"][metric] for run in known_runs])
    for cls in known_runs[0]["LightGBM"]["per_class"]:
        for metric in ("precision", "recall", "f1"):
            add_derived([run["LightGBM"]["per_class"][cls][metric] for run in known_runs])

    in_table = False
    for line in markdown.splitlines():
        if line.startswith("|"):
            if set(line.replace("|", " ").strip()) <= {"-", ":", " "}:
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            for cell in cells:
                for token in re.findall(r"(?<![A-Za-z])\d+(?:\.\d+)?", cell):
                    assert token in allowed, f"table value {token} is not sourced from FINAL-listed JSON"


def test_evaluation_summary_api_archive_is_opt_in(monkeypatch):
    from app.api import endpoints

    calls = []
    monkeypatch.setattr(evaluation_results, "build_evaluation_summary", lambda include_archive=False: calls.append(include_archive) or [])
    assert endpoints.get_evaluation_summary(include_archive=False) == {"profiles": []}
    assert endpoints.get_evaluation_summary(include_archive=True) == {"profiles": []}
    assert calls == [False, True]
