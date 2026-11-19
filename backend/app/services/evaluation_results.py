"""Read-only discovery and aggregation for completed evaluation JSON files."""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RESULTS_DIR = Path(__file__).resolve().parents[2] / "ml" / "evaluation" / "results"
FINAL_MANIFEST = RESULTS_DIR / "FINAL.json"
_IGNORED_MARKERS = ("_progress", "_capture")


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _is_ignored(path: Path) -> bool:
    name = path.name.lower()
    return (
        name.startswith("partial_")
        or any(marker in name for marker in _IGNORED_MARKERS)
        or path.parent.name.lower() == "scores"
    )


def _profile(data: dict[str, Any]) -> str:
    metadata = data.get("run_metadata") or {}
    return str(data.get("profile_name") or metadata.get("profile_name") or data.get("profile") or "full")


def _sample_fraction(data: dict[str, Any]) -> float | None:
    metadata = data.get("run_metadata") or {}
    value = data.get("sample_fraction", metadata.get("sample_fraction"))
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _manifest_entries() -> list[dict[str, Any]]:
    manifest = _read_json(RESULTS_DIR / "FINAL.json")
    if not manifest:
        return []
    return [
        entry for entry in manifest.get("results", [])
        if isinstance(entry, dict) and isinstance(entry.get("file"), str)
    ]


def _open_set_files(include_archive: bool = False) -> list[tuple[Path, dict[str, Any]]]:
    if not RESULTS_DIR.is_dir():
        return []
    rows: list[tuple[Path, dict[str, Any]]] = []
    for entry in _manifest_entries():
        if entry.get("kind") != "open_set":
            continue
        filename = Path(entry["file"])
        if filename.name != entry["file"] or filename.suffix.lower() != ".json":
            continue
        path = RESULTS_DIR / filename
        data = _read_json(path)
        if data and data.get("status") != "running":
            rows.append((path, data))
    if include_archive:
        archive_dir = RESULTS_DIR / "archive"
        paths = archive_dir.glob("open_set_*.json") if archive_dir.is_dir() else ()
        for path in paths:
            if _is_ignored(path):
                continue
            data = _read_json(path)
            if data and data.get("status") != "running":
                rows.append((path, data))
    return rows


def _run_entry(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    metadata = data.get("run_metadata") or {}
    return {
        "run_id": data.get("run_id") or path.stem.removeprefix("open_set_"),
        "profile": _profile(data),
        "seed": data.get("seed", metadata.get("seed")),
        "date": data.get("date") or datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
        "sample_fraction": _sample_fraction(data),
        "_path": path,
        "_data": data,
    }


def list_evaluation_runs(include_archive: bool = False) -> list[dict[str, Any]]:
    rows = [_run_entry(path, data) for path, data in _open_set_files(include_archive=include_archive)]
    rows.sort(key=lambda row: row["_path"].stat().st_mtime, reverse=True)
    return [
        {key: value for key, value in row.items() if not key.startswith("_")}
        for row in rows
    ]


def get_evaluation_result(run_id: str | None = None, include_archive: bool = False) -> dict[str, Any] | None:
    """Return a selected complete run and its closest matching classifier JSON."""
    entries = [_run_entry(path, data) for path, data in _open_set_files(include_archive=include_archive)]
    entries.sort(key=lambda row: row["_path"].stat().st_mtime, reverse=True)
    selected = next((row for row in entries if row["run_id"] == run_id), None) if run_id else (
        entries[0] if entries else None
    )
    if selected is None:
        return None

    chosen = selected["_data"]
    known_matches = []
    if RESULTS_DIR.is_dir():
        for path in RESULTS_DIR.glob("known_classifier_*.json"):
            if _is_ignored(path):
                continue
            data = _read_json(path)
            if not data:
                continue
            if (
                data.get("seed") == chosen.get("seed")
                and _profile(data) == _profile(chosen)
                and _sample_fraction(data) == _sample_fraction(chosen)
            ):
                allowed = {
                    entry["file"] for entry in _manifest_entries()
                    if entry.get("kind") == "known_classifier"
                }
                if path.name in allowed:
                    known_matches.append((path, data))
    known_matches.sort(key=lambda item: item[0].stat().st_mtime, reverse=True)
    known = known_matches[0] if known_matches else None

    files = [selected["_path"].name]
    response: dict[str, Any] = {
        "available": True,
        "runs": list_evaluation_runs(include_archive=include_archive),
        "run": {key: value for key, value in selected.items() if not key.startswith("_")},
        "open_set": chosen,
        "files": files,
    }
    if known:
        response["known_classifier"] = known[1]
        response["files"].insert(0, known[0].name)
    return response


def build_evaluation_summary(include_archive: bool = False) -> list[dict[str, Any]]:
    """Aggregate AUROC and unknown rejection across distinct seeds per profile."""
    # Keep only the newest complete result for a profile/seed pair.
    latest_by_profile_seed: dict[tuple[str, int], tuple[Path, dict[str, Any]]] = {}
    for path, data in _open_set_files(include_archive=include_archive):
        profile = _profile(data)
        seed = data.get("seed")
        if not isinstance(seed, int):
            continue
        key = (profile, seed)
        previous = latest_by_profile_seed.get(key)
        if previous is None or path.stat().st_mtime > previous[0].stat().st_mtime:
            latest_by_profile_seed[key] = (path, data)

    by_profile: dict[str, list[dict[str, Any]]] = {}
    for (profile, _seed), (_path, data) in latest_by_profile_seed.items():
        by_profile.setdefault(profile, []).append(data)

    summaries = []
    for profile, runs in sorted(by_profile.items()):
        if len(runs) < 2:
            continue
        families: dict[str, list[tuple[int, dict[str, Any]]]] = {}
        for run in runs:
            seed = int(run["seed"])
            for family in run.get("per_family", []):
                name = family.get("family")
                if name:
                    families.setdefault(str(name), []).append((seed, family))

        family_summaries = []
        for family_name, family_runs in sorted(families.items()):
            unknown_supports = [int(row.get("n_test_unknown", 0)) for _, row in family_runs]
            detector_values: dict[str, dict[str, list[float]]] = {}
            for _, row in family_runs:
                for detector, metrics in (row.get("detectors") or {}).items():
                    bucket = detector_values.setdefault(detector, {
                        "AUROC": [], "unknown_rejection_rate": [], "oscr_auc": [],
                        "unknown_recall": [], "known_macro_f1": [], "auprc": [],
                    })
                    for metric in bucket:
                        value = metrics.get(metric)
                        if value is not None:
                            bucket[metric].append(float(value))

            detector_summary: dict[str, Any] = {}
            for detector, metrics in sorted(detector_values.items()):
                detector_summary[detector] = {
                    metric: {
                        "mean": statistics.fmean(values) if values else None,
                        "std": statistics.pstdev(values) if len(values) > 1 else None,
                    }
                    for metric, values in metrics.items()
                }
                detector_summary[detector]["n_seeds"] = len(
                    metrics["AUROC"] or metrics["unknown_rejection_rate"]
                )
            family_summaries.append({
                "family": family_name,
                "n_seeds": len({seed for seed, _ in family_runs}),
                "low_support": any(support < 200 for support in unknown_supports),
                "detectors": detector_summary,
            })
        summaries.append({
            "profile": profile,
            "n_seeds": len(runs),
            "families": family_summaries,
        })
    return summaries
