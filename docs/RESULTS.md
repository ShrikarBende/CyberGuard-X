# Evaluation results

Generated only from saved JSON files listed in `backend/ml/evaluation/results/FINAL.json`; this report does not run evaluation.

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

| Ground truth / verdict | BENIGN | Bot | BruteForce | DosDDoS | PortScan | WebAttack | UNKNOWN_CANDIDATE |
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

- stratified random split with no timestamps (near-duplicate flows can sit in both train and test, so results are optimistic)
- single dataset, CICIDS2017, from a 2017 testbed with known labelling problems
- 15% and 50% hash samples
- 3 seeds only
- Bot (197 rows) and WebAttack (216 rows) have few unknown test rows
- PortScan is the weakest family for open-set rejection; the maximum observed unknown rejection across its detectors and seeds was 0.1813
- Bot is the weakest known class (mean F1 0.8207)
- replay families with under 100 flows are not interpretable
- the RAG test is 20 developer-written questions
- correlation scenarios and thresholds are developer-written demo values
- the user and endpoint layers have no trained model
- TFT and GAT are not implemented
