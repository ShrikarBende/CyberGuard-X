"""Run the frozen-holdout, five-seed session-disjoint network baseline."""
from __future__ import annotations

import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.evaluation.network_baseline import run_network_baseline  # noqa: E402
from make_results_md import write_results  # noqa: E402


if __name__ == "__main__":
    result = run_network_baseline()
    report = write_results(result["artifact"])
    print(json.dumps({
        "artifact": str(result["artifact"]),
        "results_report": str(report),
        "dataset_sha256": result["payload"]["dataset"]["sha256"],
        "holdout_manifest_sha256": result["payload"]["holdout"]["manifest_sha256"],
        "seeds": result["payload"]["seeds"],
    }, indent=2))
