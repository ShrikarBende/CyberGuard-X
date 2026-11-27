# Network evaluation results

This report is generated from one saved network-baseline JSON artifact. It does not run model evaluation.

Artifact: [`network_baseline_20261127T093255Z.json`](../backend/ml/evaluation/results/network_baseline_20261127T093255Z.json) (run `20261127T093255Z`).
Dataset: `CICIDS2017`; raw source-file SHA-256 fingerprint: `9bb6edafdf07613af60d43f231e3d74b3fe9a7a308e4475d28446d326f72a1bd`; processed development sample SHA-256: `c31a87dde5b5696974cd48cd1206e236dfa29a729d52bbe08e1c0917821b6a22`.
Frozen holdout: `Monday-WorkingHours.pcap_ISCX.csv`; manifest SHA-256: `701a6fca14260729a21c47c9352e62af61526643b2ce44ba28bb000a0cb9b618`; status: frozen and untouched; no holdout rows were parsed or used for fitting, calibration, or scoring.
Session split: complete source CSV capture session; CICIDS2017 source files have no Timestamp column. for each family, every development source session containing that family is held out as test; those sessions are excluded from train and validation. one complete non-test source session is selected by GroupShuffleSplit using the recorded seed.
Seeds: `42, 101, 202, 303, 404`. Development sampling: stable feature-row hash modulo 100, threshold 15; applied only to development source sessions.
Decision policy: LightGBM multiclass with current repository class weights; confidence-only open-set score (1 - maximum class probability); threshold is the 95th percentile of known-only validation scores.
Confidence intervals: percentile bootstrap of seed-level metric means (10,000 resamples). Each seed’s interval uses stratified row bootstrap of binary decisions with known/unknown/benign supports fixed (2,000 resamples).

## Per-family unknown-review metrics

Values are the mean across seed runs with the 95% bootstrap interval across those seed-level estimates. The unknown class is the named family in the row; other test labels are treated as known only when that class was present in training.

| Attack family | Test sessions | Unknown support by seed | Precision | Recall | F1 | Known FPR | Benign replay false-alert rate |
|---|---|---|---:|---:|---:|---:|---:|
| DosDDoS | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv` | 42: 48296; 101: 48296; 202: 48296; 303: 48296; 404: 48296 | 0.7849 (0.6062–0.8888) | 0.6286 (0.3531–0.7947) | 0.6804 (0.4068–0.8343) | 0.0728 (0.0604–0.0838) | 0.0728 (0.0604–0.0838) |
| PortScan | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 42: 13730; 101: 13730; 202: 13730; 303: 13730; 404: 13730 | 0.6185 (0.3638–0.8731) | 0.1364 (0.0080–0.3342) | 0.1880 (0.0154–0.4324) | 0.0223 (0.0021–0.0442) | 0.0223 (0.0021–0.0442) |
| BruteForce | `Tuesday-WorkingHours.pcap_ISCX.csv` | 42: 1379; 101: 1379; 202: 1379; 303: 1379; 404: 1379 | 0.1262 (0.0341–0.2182) | 0.3373 (0.0094–0.7269) | 0.1320 (0.0161–0.2479) | 0.0371 (0.0050–0.0708) | 0.0371 (0.0050–0.0708) |
| WebAttack | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 42: 320; 101: 320; 202: 320; 303: 320; 404: 320 | 0.0306 (0.0130–0.0493) | 0.0494 (0.0144–0.0844) | 0.0337 (0.0111–0.0562) | 0.0178 (0.0044–0.0339) | 0.0178 (0.0044–0.0339) |
| Bot | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 42: 305; 101: 305; 202: 305; 303: 305; 404: 305 | 0.0146 (0.0000–0.0438) | 0.0649 (0.0000–0.1948) | 0.0239 (0.0000–0.0716) | 0.0196 (0.0046–0.0349) | 0.0196 (0.0046–0.0349) |

## Interpretation and split audit

passed; train/validation/test source groups are pairwise disjoint for every family and seed. The final holdout was excluded from row loading, model fitting, threshold selection, and scoring; only raw file checksums were read to verify the frozen dataset identity.
The benign replay false-alert rate is measured on BENIGN rows in the development test capture sessions: BENIGN rows from held-out development capture sessions incorrectly flagged for unknown review divided by BENIGN rows in those sessions; this is an offline session replay metric, not a live-service replay run.
Unknown review semantics: confidence-threshold rejection is a triage proxy for UNKNOWN_NOVEL review, not a confirmed attack verdict.
The bootstrap interval resamples the five seed-level estimates on fixed development test sessions. It reflects seed variability, not uncertainty across a large sample of independent capture sessions.
CICIDS2017 source files contain no timestamps. Host-window features therefore remain zero in this baseline, and the final holdout consists of one complete source-file session.
Per-seed supports, session assignments, thresholds, excluded unseen test labels, and row-bootstrap intervals are recorded in the linked JSON artifact.

## Controlled ablation 1: host-window features

Ablation artifact: [`ablation_host_window_20261127T095602Z.json`](../backend/ml/evaluation/results/ablation_host_window_20261127T095602Z.json).
Status: **not_evaluable**. The final holdout remains untouched; comparison is pinned to `network_baseline_20261127T093255Z.json` with the same seeds and split rules.

| Metric | Frozen baseline | Host-window ablation | Delta |
|---|---:|---:|---:|
| Bot recall | 0.0649 (0.0000–0.1948) | n/a | n/a |
| PortScan recall | 0.1364 (0.0080–0.3342) | n/a | n/a |
| Bot precision | 0.0146 (0.0000–0.0438) | n/a | n/a |
| PortScan precision | 0.6185 (0.3638–0.8731) | n/a | n/a |
| Bot F1 | 0.0239 (0.0000–0.0716) | n/a | n/a |
| PortScan F1 | 0.1880 (0.0154–0.4324) | n/a | n/a |
| Macro unknown-review F1 | 0.2116 | n/a | n/a |
| Macro open-set rejection (recall) | 0.2433 | n/a | n/a |
| Macro benign replay false-alert rate | 0.0339 | n/a | n/a |

**Why no delta is reported:** The development CICIDS2017 files lack Timestamp and/or source IP. HostWindowAggregator requires both and emits all-zero 60-second window features without them. The frozen baseline also records host-window context as zero, so an enabled-versus-disabled model comparison on this data would not change the treatment. No model was fitted and no ablation metrics or deltas are claimed.
Required fields absent from development session headers: `source ip, timestamp`. No model was fitted for this ablation.
A valid rerun requires flow telemetry containing per-row timestamps and source-host identifiers. Do not infer timestamps from row order or derive a 60-second window from aggregate flow IAT fields.