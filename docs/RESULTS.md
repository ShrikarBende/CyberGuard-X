# Evaluation results and model provenance

This report reconciles the saved evaluation JSONs and model bundle metadata present in this checkout. Tables labeled as saved-artifact results describe those exact artifacts; newer training code does not retroactively update older bundles.

## Implemented model families and decision layers

Four trained model families are present in code and saved bundles: (1) LightGBM/XGBoost network-flow classifiers (LightGBM is the saved live classifier), (2) DAE + Isolation Forest endpoint anomaly scoring, (3) TFT user-sequence scoring, and (4) GAT host-communication scoring. Presence of a bundle is not evidence of independent ground-truth validation.

Open-set scoring uses centroid distance and confidence/energy/margin signals. Internal outcomes include `KNOWN_THREAT`, `ABSTAIN_NEEDS_REVIEW` (the explicit `decision_outcome`), and `UNKNOWN_NOVEL`; the persisted compatibility verdict for low-margin cases remains `UNKNOWN_CANDIDATE`. `KNOWN_ATTACK` is not a current code/API label. Logistic-regression stacking fuses branch scores into a calibrated 0–100 triage score, not a real-world incident probability.

## Label provenance: benchmark labels vs proxy labels

**Dataset-labeled benchmark results:** CICIDS2017 flow classification and leave-one-family-out open-set results use the dataset's labels as benchmark references. The source corpus has known labeling limits, and these labels are not independently adjudicated real-world incident ground truth. Both the standard stratified runs and the new capture-session-disjoint comparison are listed below. The saved local Sysmon bundle has no labeled benign-versus-Atomic-Red-Team evaluation metrics; that benchmark remains unavailable until separate labeled capture sets are supplied.

**Weakly supervised or synthetic proxy results:** the saved TFT metrics use heuristic sequence labels from Sysmon/CERT indicators; GAT's target is UNSW-NB15 non-benign `attack_cat`, a multi-host anomaly proxy rather than lateral-movement ground truth; the fusion meta-model uses synthetic weak labels. Do not compare these proxy metrics directly with the dataset-labeled CICIDS benchmark.

## Scenario coverage

The default scenario loader still returns four interactive demos. `generate_all_taxonomy_scenarios()` now supplies the twelve named synthetic threat scenarios plus `benign_admin` and `normal_employee_day`. These are developer-authored rule/demo fixtures, not benchmark coverage or captured attack data; `unknown_novel_zero_day` is only a synthetic proxy.

## MITRE ATT&CK knowledge metadata

The curated technique references are versioned in `backend/app/rag/knowledge_metadata.json` against Enterprise ATT&CK v20.1 (reference verified 2026-11-19). This is a project-curated subset, not a complete or automatically synchronized ATT&CK export. Technique-based mappings are implemented; ingestion of MITRE Detection Strategies and Analytics is a planned transition, not a current capability. MITRE's [version history](https://attack.mitre.org/resources/previous-versions/) records v20.1 as current for the reference date.

## Capture-session-disjoint comparison

The saved [comparison JSON](../backend/ml/evaluation/results/medium_stratified_vs_session_disjoint.json) and [Markdown report](../backend/ml/evaluation/results/medium_stratified_vs_session_disjoint.md) compare the medium CICIDS sample (50% feature-row sample, 60,000-row per-fold train cap, LightGBM confidence detector, seeds 42 and 43). Stratified values cover all ten family/seed folds. The GroupShuffleSplit session-disjoint test had unknown support for only three of ten family/seed folds; the remaining folds are explicitly listed as skipped. Intervals are across available family/seed folds and are wide for session-disjoint results.

| Split | OSCR AUC | Unknown Recall | Benign FPR | Known Macro F1 | Supported folds |
|---|---:|---:|---:|---:|---:|
| Stratified row split | 0.8239 (0.7377–0.9101) | 0.3966 (0.1622–0.6310) | 0.0294 (0.0284–0.0305) | 0.9482 (0.9369–0.9595) | 10/10 |
| Session-disjoint capture split | 0.5410 (0.1286–0.9535) | 0.0760 (0.0000–0.2200) | 0.0012 (0.0011–0.0014) | 0.1898 (0.1710–0.2086) | 3/10 |

These are dataset-labeled benchmark metrics, not independently verified incidents. The split comparison uses fewer trees and a smaller train cap than the saved full medium open-set run; it is a controlled split comparison, not a replacement result for that artifact.

## Saved branch artifact status

| Family | Saved artifact evidence | Label provenance and validation status |
|---|---|---|
| Network flow | `cicids2017_medium_lightgbm.bundle.pkl`; seed 42; CICIDS2017 medium profile | Dataset-labeled classifier and open-set reports are available below. |
| Endpoint DAE + Isolation Forest | `endpoint_behavior.bundle.pkl`; 293 Sysmon capture windows; source `real_sysmon_captures_unsupervised` | No labeled validation metrics are stored. The current bundled source collection does not establish a benign baseline; do not describe this saved artifact as a validated benign-only detector. Updated training code accepts separate benign and Atomic Red Team evaluation capture directories and stores ROC-AUC, PR-AUC, and detection at 5% benign FPR when both are supplied. |
| TFT | `user_tft.bundle.pkl`; 1,978 train sequences, 495 validation sequences; seed 42 | Saved metrics: ROC-AUC 0.99998, accuracy 0.9960, precision 0.9926, recall 0.9926. The saved artifact predates user-disjoint splitting and uses `stratified_sequence_level_80_20`; labels are heuristic weak proxies, so these values are not ground-truth performance. Newly trained bundles use user-group-disjoint validation. |
| GAT | `network_gat.bundle.pkl`; 12,000 UNSW-NB15 rows; seed 42 | No independent validation metrics are stored. `attack_cat != benign` is a proxy target, not verified lateral-movement labels. |
| Risk fusion | `risk_fusion_meta.joblib`; 4,800 synthetic weak-label train rows, 1,200 validation rows | Saved validation ROC-AUC 0.8573 and Brier score 0.1507 on synthetic proxy labels only. |

The app also contains four built-in interactive demo scenarios and a 12-scenario target taxonomy; demo/rule correlation results are not benchmark detections.

---

## Saved open-set evaluation reports

The tables below are generated from saved JSON artifacts; this document does not run an evaluation.

## Medium open-set results

AUROC and unknown rejection are mean ± sample standard deviation over saved medium seeds.

| Family | Detector | AUROC mean ± sd | Unknown rejection mean ± sd | Unknown test rows by seed | Low support |
|---|---|---:|---:|---|---|
| Bot | confidence | 0.6755 ± 0.0669 | 0.1743 ± 0.1084 | 42: 197; 43: 197; 44: 197 | Low support |
| Bot | confidence_mahalanobis_rank_average | 0.6705 ± 0.0495 | 0.2335 ± 0.0152 | 42: 197; 43: 197; 44: 197 | Low support |
| Bot | isolation_forest | 0.6167 ± 0.0170 | 0.0203 ± 0.0134 | 42: 197; 43: 197; 44: 197 | Low support |
| Bot | mahalanobis | 0.6452 ± 0.0129 | 0.0372 ± 0.0029 | 42: 197; 43: 197; 44: 197 | Low support |
| Bot | union_conf_mahalanobis | 0.6173 ± 0.0810 | 0.1201 ± 0.1510 | 42: 197; 43: 197; 44: 197 | Low support |
| BruteForce | confidence | 0.9448 ± 0.0547 | 0.7494 ± 0.4322 | 42: 899; 43: 899; 44: 899 | No |
| BruteForce | confidence_mahalanobis_rank_average | 0.9509 ± 0.0212 | 0.5599 ± 0.3067 | 42: 899; 43: 899; 44: 899 | No |
| BruteForce | isolation_forest | 0.7851 ± 0.0092 | 0.0000 ± 0.0000 | 42: 899; 43: 899; 44: 899 | No |
| BruteForce | mahalanobis | 0.8302 ± 0.0014 | 0.0019 ± 0.0006 | 42: 899; 43: 899; 44: 899 | No |
| BruteForce | union_conf_mahalanobis | 0.9047 ± 0.0867 | 0.2610 ± 0.0206 | 42: 899; 43: 899; 44: 899 | No |
| DosDDoS | confidence | 0.9558 ± 0.0110 | 0.8104 ± 0.0103 | 42: 32220; 43: 32220; 44: 32220 | No |
| DosDDoS | confidence_mahalanobis_rank_average | 0.9841 ± 0.0054 | 0.9588 ± 0.0101 | 42: 32220; 43: 32220; 44: 32220 | No |
| DosDDoS | isolation_forest | 0.9590 ± 0.0031 | 0.8122 ± 0.0079 | 42: 32220; 43: 32220; 44: 32220 | No |
| DosDDoS | mahalanobis | 0.9597 ± 0.0010 | 0.7972 ± 0.0079 | 42: 32220; 43: 32220; 44: 32220 | No |
| DosDDoS | union_conf_mahalanobis | 0.9720 ± 0.0040 | 0.8307 ± 0.0144 | 42: 32220; 43: 32220; 44: 32220 | No |
| PortScan | confidence | 0.8187 ± 0.0766 | 0.1170 ± 0.0803 | 42: 9029; 43: 9029; 44: 9029 | No |
| PortScan | confidence_mahalanobis_rank_average | 0.8673 ± 0.0372 | 0.0561 ± 0.0241 | 42: 9029; 43: 9029; 44: 9029 | No |
| PortScan | isolation_forest | 0.8083 ± 0.0189 | 0.0032 ± 0.0007 | 42: 9029; 43: 9029; 44: 9029 | No |
| PortScan | mahalanobis | 0.7864 ± 0.0011 | 0.0079 ± 0.0014 | 42: 9029; 43: 9029; 44: 9029 | No |
| PortScan | union_conf_mahalanobis | 0.7687 ± 0.0494 | 0.0347 ± 0.0251 | 42: 9029; 43: 9029; 44: 9029 | No |
| WebAttack | confidence | 0.9894 ± 0.0058 | 0.9599 ± 0.0134 | 42: 216; 43: 216; 44: 216 | Borderline support |
| WebAttack | confidence_mahalanobis_rank_average | 0.9351 ± 0.0037 | 0.0309 ± 0.0271 | 42: 216; 43: 216; 44: 216 | Borderline support |
| WebAttack | isolation_forest | 0.6416 ± 0.0319 | 0.0123 ± 0.0214 | 42: 216; 43: 216; 44: 216 | Borderline support |
| WebAttack | mahalanobis | 0.7384 ± 0.0139 | 0.0324 ± 0.0046 | 42: 216; 43: 216; 44: 216 | Borderline support |
| WebAttack | union_conf_mahalanobis | 0.9949 ± 0.0006 | 0.9753 ± 0.0096 | 42: 216; 43: 216; 44: 216 | Borderline support |

`union_conf_mahalanobis` uses the 97.5th percentile of each component; every other detector uses the 95th percentile of known validation scores.
The 50% sample is selected by feature-row hash and is identical across seeds; the seed changes the stratified per-source train/validation/test split and seeded model randomness.

### How to read the open-set tables

With 3 seeds, detectors whose mean ± sd ranges overlap are not ranked. Bootstrap intervals, where shown, reflect test-sampling noise only.

## Sample-size sensitivity

AUROC and unknown rejection are shown side by side for the light and medium seed-42 runs.

| Family | Detector | Light AUROC | Medium AUROC | Light unknown rejection | Medium unknown rejection |
|---|---|---:|---:|---:|---:|
| Bot | confidence | 0.4726 | 0.7440 | 0.2623 | 0.2538 |
| Bot | isolation_forest | 0.6360 | 0.6359 | 0.0164 | 0.0355 |
| Bot | mahalanobis | 0.6616 | 0.6582 | 0.0164 | 0.0406 |
| Bot | confidence_mahalanobis_rank_average | 0.5585 | 0.7246 | 0.3279 | 0.2487 |
| BruteForce | confidence | 0.9810 | 0.9802 | 1.0000 | 1.0000 |
| BruteForce | isolation_forest | 0.7683 | 0.7939 | 0.0000 | 0.0000 |
| BruteForce | mahalanobis | 0.8345 | 0.8318 | 0.0036 | 0.0022 |
| BruteForce | confidence_mahalanobis_rank_average | 0.9613 | 0.9657 | 0.6993 | 0.8265 |
| DosDDoS | confidence | 0.4325 | 0.9657 | 0.0793 | 0.8190 |
| DosDDoS | isolation_forest | 0.9562 | 0.9579 | 0.8266 | 0.8179 |
| DosDDoS | mahalanobis | 0.9598 | 0.9585 | 0.8058 | 0.7912 |
| DosDDoS | confidence_mahalanobis_rank_average | 0.8094 | 0.9893 | 0.1525 | 0.9677 |
| PortScan | confidence | 0.5201 | 0.8905 | 0.0830 | 0.1425 |
| PortScan | isolation_forest | 0.8111 | 0.8287 | 0.0036 | 0.0037 |
| PortScan | mahalanobis | 0.7841 | 0.7856 | 0.0120 | 0.0091 |
| PortScan | confidence_mahalanobis_rank_average | 0.6954 | 0.9074 | 0.0870 | 0.0818 |
| WebAttack | confidence | 0.9807 | 0.9922 | 0.9062 | 0.9444 |
| WebAttack | isolation_forest | 0.6446 | 0.6620 | 0.0000 | 0.0370 |
| WebAttack | mahalanobis | 0.7631 | 0.7271 | 0.0625 | 0.0370 |
| WebAttack | confidence_mahalanobis_rank_average | 0.9395 | 0.9356 | 0.0625 | 0.0509 |

Confidence-based AUROC differed strongly between the light (15% sample, 60,000-row cap) and medium (50%, 150,000-row cap) profiles on DosDDoS and PortScan; anomaly detectors changed little. The cause was not isolated.

## Replay summary

Replay metadata: model_version=cicids2017-medium-v1; profile=not recorded; rows=20000; split_type=not recorded; seed=42; sampling_method=not recorded.

### Confusion matrix

| Dataset label / verdict | BENIGN | Bot | BruteForce | DosDDoS | PortScan | WebAttack | UNKNOWN_CANDIDATE |
|---|---:|---:|---:|---:|---:|---:|---:|
| BENIGN | 16074 | 0 | 0 | 0 | 0 | 0 | 515 |
| Bot | 0 | 9 | 0 | 0 | 0 | 0 | 7 |
| BruteForce | 0 | 0 | 72 | 0 | 0 | 0 | 2 |
| DosDDoS | 0 | 0 | 0 | 2439 | 0 | 0 | 134 |
| PortScan | 0 | 0 | 0 | 0 | 372 | 0 | 359 |
| WebAttack | 0 | 0 | 0 | 0 | 0 | 16 | 1 |

### Per-family replay metrics

| Family | Support | Low support | Alerted / false-alert rate | Correct-class recall / specificity |
|---|---:|---|---:|---:|
| BENIGN | 16589 | No | false-alert rate: 0.0310 | specificity: 0.9690 |
| Bot | 16 | Yes | alerted rate: 1.0000 | correct-class recall: 0.5625 |
| BruteForce | 74 | Yes | alerted rate: 1.0000 | correct-class recall: 0.9730 |
| DosDDoS | 2573 | No | alerted rate: 1.0000 | correct-class recall: 0.9479 |
| PortScan | 731 | No | alerted rate: 1.0000 | correct-class recall: 0.5089 |
| WebAttack | 17 | Yes | alerted rate: 1.0000 | correct-class recall: 0.9412 |

## RAG retrieval

20 developer-written questions, indicative only.

- Questions: 20
- Model: `all-MiniLM-L6-v2`
- FAISS backend: `faiss`
- Knowledge-file hash: `10e29d7f76ab448200b323b3108b2f61929ccaf5a41f5ecdb2d7b78aa00dccc0`
- Hit@1: 0.8500
- Hit@3: 0.9000

The new quality runner was executed on 2026-11-24 using the NumPy index backend. It confirms the same Hit@1/Hit@3 and adds MRR. Groundedness and MITRE mapping metrics were unavailable because this run used retrieval questions only, without generated reports or labeled mapping cases.

| Run date | Index backend | Questions | Hit@1 | Hit@3 | MRR | Groundedness | MITRE mapping F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| 2026-11-24 | NumPy | 20 | 0.8500 | 0.9000 | 0.8750 | n/a | n/a |

Missed questions and top retrieved source:

- What traffic pattern can indicate network service discovery? — expected `t1046_network_discovery.md`, top source `t1498_network_denial_of_service.md`.
- What evidence should be preserved before containing a suspicious host? — expected `ir_evidence_containment.md`, top source `t1190_public_facing_app.md`.

## Known-class classifier metrics

Mean ± sample standard deviation over the medium seeds.

| Model | Macro-F1 mean ± sd | Accuracy mean ± sd |
|---|---:|---:|
| LightGBM | 0.9667 ± 0.0010 | 0.9994 ± 0.0000 |

### Per-class metrics

| Model | Class | Precision mean ± sd | Recall mean ± sd | F1 mean ± sd | Support by seed |
|---|---|---:|---:|---:|---|
| LightGBM | BENIGN | 0.9999 ± 0.0001 | 0.9994 ± 0.0000 | 0.9996 ± 0.0000 | 42: 207268; 43: 207268; 44: 207268 |
| LightGBM | Bot | 0.7221 ± 0.0262 | 0.9526 ± 0.0394 | 0.8207 ± 0.0062 | 42: 197; 43: 197; 44: 197 |
| LightGBM | BruteForce | 0.9989 ± 0.0019 | 0.9996 ± 0.0006 | 0.9993 ± 0.0013 | 42: 899; 43: 899; 44: 899 |
| LightGBM | DosDDoS | 0.9994 ± 0.0002 | 0.9997 ± 0.0001 | 0.9995 ± 0.0002 | 42: 32220; 43: 32220; 44: 32220 |
| LightGBM | PortScan | 0.9961 ± 0.0001 | 0.9991 ± 0.0005 | 0.9976 ± 0.0003 | 42: 9029; 43: 9029; 44: 9029 |
| LightGBM | WebAttack | 0.9906 ± 0.0081 | 0.9769 ± 0.0122 | 0.9837 ± 0.0093 | 42: 216; 43: 216; 44: 216 |

Lowest-F1 known class from these results: Bot (LightGBM).

Accuracy is shown last in the summary table because benign flows dominate the test set.

## Metric definitions

- AUROC: how well the detector score ranks held-out unknown rows above known rows.
- Unknown rejection: the fraction of held-out unknown rows rejected at the 5% known false-reject threshold selected using known validation data.
- Alerted rate: the fraction of replay rows that produced an alert.
- Correct-class recall: the fraction of rows in a family assigned that correct family verdict.

## Limitations

- Older saved CICIDS runs use stratified row splits with possible capture-session leakage. The new session-disjoint comparison is available, but only 3/10 family/seed folds had unknown support.
- single dataset, CICIDS2017, from a 2017 testbed with known labelling problems
- 15% and 50% hash samples
- 3 seeds only
- Bot (197 rows) and WebAttack (216 rows) have few unknown test rows
- PortScan is the weakest family for open-set rejection; the maximum observed unknown rejection across its detectors and seeds was 0.1813
- Bot is the weakest known class (mean F1 0.8207)
- replay families with under 100 flows are not interpretable
- the original RAG retrieval benchmark is 20 developer-written questions; the expanded 50-case suite is also developer-authored
- correlation scenarios and thresholds are developer-written demo values; the full synthetic taxonomy is not captured or benchmark attack data
- endpoint evaluation against labeled benign and Atomic Red Team Sysmon captures is not available in the saved artifact; separate labeled capture directories are required
- TFT validation metrics in the saved bundle use weak labels and a sequence-level random split; the current training code now groups validation by user
- GAT and fusion metrics use non-ground-truth proxy labels

## Additional evaluation metrics (implementation status)

The known-class evaluation now emits per-class AUPRC, macro AUPRC, Cohen's kappa,
and balanced accuracy in each newly generated result JSON. The currently documented
seed summaries predate this change and do not contain the class probability arrays
needed to reconstruct AUPRC, so no historical values are inferred here.

| Evaluation | New result fields | Current reported value |
|---|---|---|
| Known-class classification | Per-class AUPRC, macro AUPRC | Pending a fresh classifier run |
| Known-class classification | Cohen's kappa, balanced accuracy | Emitted by the next run; not present in saved seed summaries |

The open-set run now also writes `oscr_evaluation_summary.json` with macro OSCR AUC,
FPR95, unknown recall, and sampled curve points for the primary fused detector.
Existing open-set artifacts already include per-family OSCR curves; the standalone
summary is written by a subsequent evaluation run.

| Open-set artifact | OSCR AUC | FPR95 | Unknown recall | Curve points |
|---|---:|---:|---:|---|
| Standalone fused-detector summary | Pending a fresh open-set run | Pending | Pending | Up to 201 sampled points per family |

The RAG quality runner writes `rag_quality_evaluation.json` with Hit@1, Hit@3, and
MRR for the 50-case suite. Its extractive groundedness score is based on source
citations and ATT&CK identifiers; MITRE mapping precision, recall, and F1 still
require labeled mapping cases.

## Performance hardening and expanded RAG suite

Session-disjoint feature sanitization is opt-in in `build_full_pipeline()` and removes topology/capture identifiers before scaling. The comprehensive runner enables it for session-disjoint runs. `HostWindowAggregator` exposes four rolling source-host features for replay/stream callers; existing saved bundles do not consume them.

LightGBM training applies balanced class weights and a 2.5 multiplier for the Bot class by default. This is a training policy change, not evidence that Bot precision or recall has improved; a fresh benchmark is needed. Open-set calibration can be enabled per predicted family using known-only validation quantiles. The optional Youden/geometric-mean mode accepts a separately labeled calibration set; the held-out family remains excluded from threshold selection. FPR95 continues to be calculated on the test fold as an evaluation metric.

The confidence-gated correlation path suppresses only borderline network-only alerts without rule, endpoint, or user corroboration. Raw events remain stored. The 0.5% target is not asserted as achieved without a replay benchmark.

The expanded RAG run on 2026-11-24 used 50 labeled retrieval cases (20 direct ATT&CK, 15 adversarial, 15 multi-hop) and deterministic extractive reports. These results supersede the earlier pre-hybrid 50-case run recorded in the original baseline section; the original 20-question retrieval baseline remains historical:

| Questions | Hit@1 | Hit@3 | MRR | Context precision | Groundedness | Hallucination rate |
|---:|---:|---:|---:|---:|---:|---:|
| 50 | 0.6200 | 0.8000 | 0.6900 | 0.2667 | 0.5602 | 0.4398 |

Groundedness checks citations and ATT&CK identifiers in deterministic extractive answers against retrieved chunks. It is a narrower proxy than human-annotated factual faithfulness. Context precision counts only chunks matching each case's expected source file. Compared with the earlier recorded 50-case run (Hit@1 0.64, Hit@3 0.82, MRR 0.72, groundedness 0.5618, context precision 0.2733), the current retrieval change did not improve these aggregate measures. It did pass the targeted exact MITRE technique rank-1 test. These measurements expose retrieval and support gaps; they do not establish answer quality for an external LLM generation path.

The newly rerun medium session comparison used a 50% sample, seeds 42 and 43, 60,000-row training caps, and the confidence detector. It uses the session-invariant sanitizer on the session-disjoint arm and updated balanced class weights. The artifact is `backend/ml/evaluation/results/medium_stratified_vs_session_disjoint.json`:

| Split | OSCR AUC | Unknown recall | Benign FPR | Known macro-F1 |
|---|---:|---:|---:|---:|
| Stratified random | 0.7992 (95% CI 0.6555–0.9429) | 0.4743 (0.2369–0.7118) | 0.0298 (0.0288–0.0308) | 0.9467 (0.9363–0.9571) |
| Session-disjoint | 0.5996 (0.2208–0.9785) | 0.1716 (0.0000–0.5055) | 0.0027 (0.0018–0.0036) | 0.1897 (0.1711–0.2084) |

Only 3 of 10 session-disjoint family/seed folds had held-out unknown support; the interval is wide and the mean is not directly comparable to historical single-split values. The new comparison still shows a large generalization gap. The comprehensive benchmark runner is a separate light-profile run and records its configuration and metrics in `backend/ml/evaluation/results/comprehensive_benchmark_run.json`.

<!-- COMPREHENSIVE_BENCHMARKS:START -->
## Comprehensive benchmark comparison (generated)

| Metric | Historical stratified baseline | Historical session-disjoint baseline | Current run |
|---|---:|---:|---:|
| Known Macro-F1 | 0.9482 | 0.1898 | 0.1687 |
| Known Macro-AUPRC | n/a | n/a | 0.9555 |
| Balanced accuracy | n/a | n/a | 0.3228 |
| Cohen's kappa | n/a | n/a | 0.0226 |
| Open-set OSCR AUC | 0.8239 | 0.5410 | 0.2635 |
| Open-set FPR95 | n/a | n/a | 0.8918 |
| Open-set unknown recall | 0.3966 | 0.0760 | 0.0007 |
| RAG Hit@1 / Hit@3 / MRR | 0.8500 / 0.9000 / n/a | n/a | 0.6200 / 0.8000 / 0.6900 |
| RAG groundedness | n/a | n/a | 0.5602 |

Generated at 2026-11-24T13:25:30.603933+00:00. Historical values are the saved results described above; current values are from artifacts generated by this run. Groundedness covers extractive answer citations and ATT&CK identifiers.

The current run used a 15% session-disjoint sample, a 30,000-row open-set training cap, and the confidence-only detector for bounded execution. Several held-out groups had zero test support (including Bot, BruteForce, and DosDDoS in the known classifier, and three of five open-set families), so these diagnostic aggregates are not directly comparable to the historical baselines. Macro-AUPRC averages only classes with both positive and negative test examples; Bot precision is not measurable in this run.
<!-- COMPREHENSIVE_BENCHMARKS:END -->

<!-- GENERATED AGENT EVALUATION: START -->
## Agent investigation evaluation (generated)

Model: `FakeLLM-scripted-v1`; date: `2026-11-25`; seed: `42`; sample size: 30; used FakeLLM: `true`.
Inputs: 15 held-out CICIDS replay rows and 15 synthetic demo rows. Demo-derived values are synthetic.
FakeLLM scripted evaluation validates plumbing only. It does not measure real-model quality or support an improvement claim.

| Arm | Valid citation rate before validator | Unsupported technique rate | ATT&CK precision (expected classes) | ATT&CK recall (expected classes) | Mean steps | Mean tool calls | Mean latency seconds | Fallback rate | Limit reached rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Deterministic baseline | n/a | n/a | 0.0000 | 0.0000 | 5.0000 | 0.0000 | 1.3358 | 0.0000 | 0.0000 |
| Agent (FakeLLM) | 0.0000 | 1.0000 | 0.0000 | 0.0000 | 4.0000 | 1.0000 | 1.3503 | 0.0000 | 0.0000 |

Injection guard suite: 12/12 passed with FakeLLM; scope is scripted guard verification only.
Regression suite F1–F5: passed; FakeLLM and deterministic unit-style regression checks; plumbing evidence only.
Expected ATT&CK techniques are versioned in `backend/ml/evaluation/expected_techniques.json`; precision and recall include only listed classes.

<!-- GENERATED AGENT EVALUATION: END -->
