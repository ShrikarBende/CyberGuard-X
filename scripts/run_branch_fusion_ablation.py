"""Write a provenance and feasibility record for the branch/fusion ablation.

This guard prevents incomparable branch metrics from being presented as a
fusion ablation. Current branch data and labels are from separate cohorts, and
the repository has no entity-keyed joint fusion evaluation set.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
RESULTS = BACKEND / "ml" / "evaluation" / "results"
HOLDOUT = BACKEND / "ml" / "evaluation" / "holdout_manifest.json"
NETWORK_BASELINE = RESULTS / "network_baseline_20261127T093255Z.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> Path:
    sysmon = BACKEND / "datasets" / "sysmon"
    unsw = BACKEND / "datasets" / "unsw_nb15"
    fusion_data = BACKEND / "datasets" / "fusion_training.csv"
    endpoint_benign = sysmon / "benign"
    endpoint_attack_eval = sysmon / "atomic_red_team"
    capture_sessions = sorted(path.name for path in (sysmon / "captures").iterdir() if path.is_dir()) if (sysmon / "captures").is_dir() else []
    unsw_files = sorted(path.name for path in unsw.glob("UNSW-NB15_[1-4].csv"))
    fusion_has_entity_key = False
    if fusion_data.is_file():
        import pandas as pd
        header = set(pd.read_csv(fusion_data, nrows=0).columns)
        fusion_has_entity_key = bool(header & {"device_id", "user_id", "scenario_id", "capture_session"})

    run_time = datetime.now(timezone.utc)
    run_id = run_time.strftime("%Y%m%dT%H%M%SZ")
    output = RESULTS / f"branch_fusion_ablation_{run_id}.json"
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output.name}")

    provenance = {
        "endpoint_autoencoder_iforest": {
            "training_source_available": "synthetic benign fallback; real OTRF Sysmon attack captures are present",
            "labeled_holdout_available": bool(endpoint_benign.is_dir() and endpoint_attack_eval.is_dir()),
            "available_attack_capture_sessions": capture_sessions,
            "label_scope": "No paired benign and Atomic Red Team entity-disjoint evaluation directories are present.",
            "entity_disjoint_evaluation": "not run; no labeled benign/attack capture pair to split by capture session",
        },
        "user_sequence_tft": {
            "training_source_available": "OTRF Sysmon public attack captures; CERT logon cohort not present",
            "label_source": "heuristic risk labels from failed logons, host transitions, elevation and command activity",
            "label_scope": "Proxy labels are generated from the same input indicators; not verified account-takeover ground truth.",
            "entity_disjoint_evaluation": "training code groups by user for its validation split, but this cohort is not aligned to Endpoint, GAT or Fusion test entities",
        },
        "host_graph_gat": {
            "training_source_available": "UNSW-NB15 captured network benchmark",
            "available_files": unsw_files,
            "label_source": "attack_cat non-benign indicator",
            "label_scope": "Network attack-category proxy; not labeled lateral movement ground truth.",
            "entity_disjoint_evaluation": "existing trainer is transductive on one graph and does not save an entity-disjoint test evaluation",
        },
        "calibrated_fusion_meta_classifier": {
            "training_data_path": str(fusion_data.relative_to(ROOT)).replace("\\", "/"),
            "joint_training_file_present": fusion_data.is_file(),
            "joint_training_file_has_entity_key": fusion_has_entity_key,
            "fallback_training_source": "synthetic_weak_labels_v1",
            "label_scope": "Generated weak incident labels from synthetic branch-score profiles.",
            "split_scope": "Current trainer uses row-level stratified train/validation split, not entity/session-disjoint splits.",
        },
    }
    reasons = [
        "The three standalone branches use distinct cohorts and targets, so their metrics are not estimates on a common evaluation population.",
        "No shared entity-keyed labeled cohort contains aligned endpoint, user-sequence, and graph inputs with independent incident ground truth.",
        "The available Fusion artifact is trained from synthetic weak-label profiles (or an absent optional CSV) and has no matching branch test rows.",
        "Consequently, fusion-versus-strongest-branch deltas for F1, AUPRC, or FPR cannot be estimated without fabricating aligned examples or labels.",
    ]
    payload = {
        "artifact_schema_version": 1,
        "run_id": run_id,
        "created_at_utc": run_time.isoformat(),
        "ablation": "Endpoint + User/Sequence + Host-Graph standalone versus calibrated Fusion Meta-Classifier",
        "status": "not_evaluable",
        "seed_plan": [42, 101, 202, 303, 404],
        "required_split_policy": "group by device_id, user_id, scenario_id or capture_session; keep all related entities wholly within one split",
        "data_provenance": provenance,
        "entity_disjoint_evaluation": "not run because the required shared cohort and independent labels are unavailable",
        "metrics": None,
        "reasons": reasons,
        "protected_artifacts": {
            "holdout_manifest_sha256": sha256(HOLDOUT),
            "network_baseline_sha256": sha256(NETWORK_BASELINE),
            "status": "hashed for integrity verification only; neither artifact was modified or used for training or scoring",
        },
        "requirements_for_valid_rerun": [
            "A common, independently labeled multi-modal telemetry cohort with aligned device, user and capture/scenario identifiers.",
            "Benign and attack endpoint captures separated by capture session; user-sequence incident labels not derived from the model input features.",
            "A graph cohort with declared host-disjoint train/calibration/test components and independent attack labels.",
            "Saved out-of-fold branch scores for the same entities, then fit/calibrate Fusion on training entities and evaluate all branches on the identical untouched test entities.",
        ],
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(output), "status": payload["status"],
                      "fusion_training_file_present": fusion_data.is_file(),
                      "endpoint_labeled_pair_present": payload["data_provenance"]["endpoint_autoencoder_iforest"]["labeled_holdout_available"]}, indent=2))
    return output


if __name__ == "__main__":
    main()
