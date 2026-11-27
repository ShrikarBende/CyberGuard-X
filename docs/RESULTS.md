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
## Controlled ablation 2: standalone branches versus calibrated fusion

Feasibility artifact: [`branch_fusion_ablation_20261127T101010Z.json`](../backend/ml/evaluation/results/branch_fusion_ablation_20261127T101010Z.json).
Status: **not_evaluable**. Required multi-seed metrics are not available because the branch data do not form a shared entity-disjoint labeled cohort.

| Branch | Available data and label provenance | Entity-disjoint standalone metrics |
|---|---|---|
| Endpoint (Autoencoder + iForest) | synthetic benign fallback; real OTRF Sysmon attack captures are present | Not evaluable: No paired benign and Atomic Red Team entity-disjoint evaluation directories are present. |
| User/Sequence (TFT) | OTRF Sysmon public attack captures; CERT logon cohort not present; heuristic risk labels from failed logons, host transitions, elevation and command activity | Not evaluated here: Proxy labels are generated from the same input indicators; not verified account-takeover ground truth. |
| Host-Graph (GAT) | UNSW-NB15 captured network benchmark; labels use `attack_cat non-benign indicator` | Not evaluated here: Network attack-category proxy; not labeled lateral movement ground truth. |
| Calibrated Fusion Meta-Classifier | `synthetic_weak_labels_v1`; Generated weak incident labels from synthetic branch-score profiles. | Not comparable: Current trainer uses row-level stratified train/validation split, not entity/session-disjoint splits. |

| Comparison metric | Strongest standalone branch | Fusion on same held-out entities | Delta |
|---|---:|---:|---:|
| Precision / Recall / F1 / AUPRC / FPR | n/a | n/a | n/a |

No fusion-improvement claim is made. Endpoint captures, user sequences, UNSW graph flows and Fusion training labels come from distinct cohorts and targets; the existing saved metrics cannot be paired into one test set. Synthetic fallback results are not real captured-log performance, and heuristic or attack-category proxy labels are not independent incident ground truth.

The holdout manifest and frozen network baseline were hashed for integrity verification only; they were not modified, used for training, or scored.

A valid rerun requires one independently labeled multi-modal cohort with aligned user, device, and capture/scenario identifiers. Split those entities into train, calibration, and test groups first; generate out-of-fold branch scores for training entities; fit/calibrate Fusion on training groups only; then compare each standalone branch and Fusion on the exact same untouched test entities.
## Controlled ablation 3: RAG retrieval and analyst-query benchmark

Artifact: [`rag_ablation_20261127T102823Z.json`](../backend/ml/evaluation/results/rag_ablation_20261127T102823Z.json).
Scope: curated local knowledge base plus 50-case labeled RAG benchmark; 20 existing direct mapping questions and 15 existing multi-hop questions from the repository test benchmark, plus 15 labeled evidence-missing, prompt-injection, and remediation-refusal cases authored for this evaluation.
Knowledge-base SHA-256: `2b4691081d8d30f49f6128b85cf8e37ef106a8edc4f76bbe97a541adf4f042da`. Execution was deterministic and local-only: precomputed local chunk vectors and cached embedding model only; no LLM or live service was invoked.
Technique labels: Expected source files and technique sets are explicit benchmark labels; multi-hop technique sets are analyst-authored annotations. Abstention/refusal labels are policy test expectations, not field analyst judgments.

### Retrieval and answer-quality metrics

Values are means with 95% query-bootstrap confidence intervals. All retrieval configurations use the identical 50 queries and local chunk corpus.

| Retrieval configuration | Hit@1 | Hit@3 | MRR | Technique precision | Technique recall | Technique F1 | Citation grounding | Abstention/refusal accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Dense cosine | 0.560 (0.420–0.700) | 0.720 (0.580–0.840) | 0.630 (0.503–0.750) | 0.593 (0.512–0.675) | 0.906 (0.815–0.981) | 0.716 (0.641–0.781) | 1.000 (1.000–1.000) | 1.000 (1.000–1.000) |
| BM25 lexical | 0.500 (0.360–0.640) | 0.740 (0.620–0.860) | 0.607 (0.490–0.720) | 0.605 (0.512–0.707) | 0.868 (0.778–0.958) | 0.713 (0.641–0.783) | 1.000 (1.000–1.000) | 1.000 (1.000–1.000) |
| Hybrid BM25 + dense RRF | 0.520 (0.380–0.660) | 0.780 (0.660–0.880) | 0.623 (0.507–0.733) | 0.545 (0.472–0.627) | 0.906 (0.820–0.980) | 0.681 (0.623–0.738) | 1.000 (1.000–1.000) | 1.000 (1.000–1.000) |

### Retrieval by query category

| Configuration | Category | Cases | Hit@1 | Hit@3 | MRR | Technique F1 | Citation grounding |
|---|---|---:|---:|---:|---:|---:|---:|
| Dense cosine | evidence_missing_abstention | 5 | 0.200 (0.000–0.600) | 0.800 (0.400–1.000) | 0.433 (0.167–0.733) | n/a | n/a |
| Dense cosine | exact_attack_lookup | 20 | 0.850 (0.700–1.000) | 0.900 (0.750–1.000) | 0.875 (0.725–1.000) | 0.576 (0.500–0.655) | 1.000 (1.000–1.000) |
| Dense cosine | multi_stage_triage | 15 | 0.600 (0.333–0.867) | 0.867 (0.667–1.000) | 0.722 (0.522–0.900) | 0.827 (0.747–0.895) | 1.000 (1.000–1.000) |
| Dense cosine | prompt_injection_resistance | 5 | 0.200 (0.000–0.600) | 0.200 (0.000–0.600) | 0.200 (0.000–0.600) | n/a | 1.000 (1.000–1.000) |
| Dense cosine | remediation_execution_refusal | 5 | 0.000 (0.000–0.000) | 0.000 (0.000–0.000) | 0.000 (0.000–0.000) | n/a | n/a |
| BM25 lexical | evidence_missing_abstention | 5 | 0.400 (0.000–0.800) | 0.600 (0.200–1.000) | 0.500 (0.100–0.900) | n/a | n/a |
| BM25 lexical | exact_attack_lookup | 20 | 0.750 (0.550–0.901) | 0.900 (0.750–1.000) | 0.825 (0.675–0.950) | 0.557 (0.484–0.630) | 1.000 (1.000–1.000) |
| BM25 lexical | multi_stage_triage | 15 | 0.533 (0.267–0.800) | 0.733 (0.467–0.933) | 0.611 (0.389–0.822) | 0.853 (0.781–0.917) | 1.000 (1.000–1.000) |
| BM25 lexical | prompt_injection_resistance | 5 | 0.000 (0.000–0.000) | 0.400 (0.000–0.800) | 0.167 (0.000–0.367) | n/a | 1.000 (1.000–1.000) |
| BM25 lexical | remediation_execution_refusal | 5 | 0.000 (0.000–0.000) | 0.600 (0.200–1.000) | 0.267 (0.067–0.467) | n/a | n/a |
| Hybrid BM25 + dense RRF | evidence_missing_abstention | 5 | 0.600 (0.200–1.000) | 1.000 (1.000–1.000) | 0.733 (0.467–1.000) | n/a | n/a |
| Hybrid BM25 + dense RRF | exact_attack_lookup | 20 | 0.850 (0.700–1.000) | 0.950 (0.850–1.000) | 0.892 (0.758–1.000) | 0.537 (0.514–0.571) | 1.000 (1.000–1.000) |
| Hybrid BM25 + dense RRF | multi_stage_triage | 15 | 0.400 (0.133–0.667) | 0.800 (0.600–1.000) | 0.556 (0.367–0.756) | 0.811 (0.761–0.857) | 1.000 (1.000–1.000) |
| Hybrid BM25 + dense RRF | prompt_injection_resistance | 5 | 0.000 (0.000–0.000) | 0.200 (0.000–0.600) | 0.100 (0.000–0.300) | n/a | 1.000 (1.000–1.000) |
| Hybrid BM25 + dense RRF | remediation_execution_refusal | 5 | 0.000 (0.000–0.000) | 0.400 (0.000–0.800) | 0.167 (0.000–0.367) | n/a | n/a |

### Abstention and refusal by category

| Category | Cases | Accuracy (95% CI) |
|---|---:|---:|
| evidence_missing_abstention | 5 | 1.000 (1.000–1.000) |
| prompt_injection_resistance | 5 | 1.000 (1.000–1.000) |
| remediation_execution_refusal | 5 | 1.000 (1.000–1.000) |

Citation grounding is the fraction of citations resolving to a chunk in the retrieved context (160/160 hybrid citations). It measures the deterministic extractive path only; it does not measure LLM answer quality.
Technique precision/recall/F1 compare retrieved-document ATT&CK technique candidates with the hand-labeled technique sets (33 answerable mapping cases). Abstention/refusal accuracy checks local deterministic policy behavior on 15 labeled safety cases; its perfect score is a code-path benchmark, not a human analyst or adversarial robustness study.