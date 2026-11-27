"""Record whether CICIDS2017 can support a 60-second host-window ablation.

The checked-in CICIDS2017 flow CSVs are anonymized and omit source IP and
Timestamp. Without both fields, HostWindowAggregator emits zero window values;
running a nominal enabled/disabled comparison would not be a valid ablation.
This guard writes a timestamped feasibility artifact and never opens the frozen
holdout CSV or modifies its manifest.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "backend" / "ml" / "evaluation" / "results"
BASELINE = RESULTS / "network_baseline_20261127T093255Z.json"
DATA = ROOT / "backend" / "datasets" / "trafficlabelling"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_header(path: Path) -> set[str]:
    # Read only the first CSV record; never load or inspect holdout rows.
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        return {item.strip().lower() for item in next(csv.reader(stream))}


def main() -> Path:
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    if baseline.get("run_status") != "complete":
        raise RuntimeError("The frozen baseline artifact is incomplete")

    dev_files = baseline["dataset"]["source_file_sha256"]
    holdout_files = set(baseline["holdout"]["source_sessions"])
    required = {"timestamp", "source ip"}
    findings = []
    for record in dev_files:
        filename = record["file"]
        if filename in holdout_files:
            continue
        path = DATA / filename
        if not path.is_file():
            findings.append({"source_file": filename, "missing_file": True})
            continue
        header = _normalized_header(path)
        missing = sorted(required - header)
        if missing:
            findings.append({"source_file": filename, "missing_required_window_fields": missing})

    run_time = datetime.now(timezone.utc)
    run_id = run_time.strftime("%Y%m%dT%H%M%SZ")
    output = RESULTS / f"ablation_host_window_{run_id}.json"
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output.name}")
    payload = {
        "artifact_schema_version": 1,
        "run_id": run_id,
        "created_at_utc": run_time.isoformat(),
        "ablation": "60-second host/source sliding-window features",
        "status": "not_evaluable" if findings else "ready_for_implementation",
        "baseline_artifact": BASELINE.name,
        "baseline_artifact_sha256": _sha256(BASELINE),
        "dataset": baseline["dataset"],
        "seeds": baseline["seeds"],
        "split_rules": baseline["split_rules"],
        "holdout": {
            "source_sessions": baseline["holdout"]["source_sessions"],
            "manifest_sha256": baseline["holdout"]["manifest_sha256"],
            "status": "untouched; no holdout CSV opened or parsed",
        },
        "feature_requirements": sorted(required),
        "development_header_findings": findings,
        "reason": (
            "The development CICIDS2017 files lack Timestamp and/or source IP. "
            "HostWindowAggregator requires both and emits all-zero 60-second "
            "window features without them. The frozen baseline also records "
            "host-window context as zero, so an enabled-versus-disabled model "
            "comparison on this data would not change the treatment. No model "
            "was fitted and no ablation metrics or deltas are claimed."
        ) if findings else None,
        "metrics": None,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(output), "status": payload["status"],
                      "development_sessions_missing_fields": len(findings)}, indent=2))
    return output


if __name__ == "__main__":
    main()
