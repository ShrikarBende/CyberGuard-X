# Phase 2 Step A — Session-disjoint error analysis

Baseline artifact: `backend/ml/evaluation/results/network_baseline_20261127T113549Z.json` (run `20261127T113549Z`); dataset SHA-256 `9bb6edafdf07613af60d43f231e3d74b3fe9a7a308e4475d28446d326f72a1bd`; processed development sample SHA-256 `c31a87dde5b5696974cd48cd1206e236dfa29a729d52bbe08e1c0917821b6a22`.
The report reuses the frozen Phase 1 development sessions and seeds `42, 101, 202, 303, 404`. Frozen Monday holdout data were not loaded. No model/config/split was changed; the existing LightGBM baseline was refit only to produce diagnostic known-class confusion matrices. Feature AUC is descriptive on the already held-out family sessions and was not used for selection, tuning, or model changes.

## Current open-set weakness and test-session support

These are the baseline unknown-review F1 values from the session-disjoint five-seed artifact; interval is the seed-bootstrap 95% CI. Each target’s held-out evaluation is drawn from the listed source capture sessions, not independent sessions per seed.

| Target family | Unknown test rows per seed | Held-out source sessions | Unknown-review F1 (95% seed CI) |
|---|---:|---|---:|
| Bot | 305 | Friday-WorkingHours-Morning.pcap_ISCX.csv | 0.0239 (0.0000–0.0716) |
| WebAttack | 320 | Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 0.0337 (0.0111–0.0562) |
| BruteForce | 1379 | Tuesday-WorkingHours.pcap_ISCX.csv | 0.1320 (0.0161–0.2479) |
| PortScan | 13730 | Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 0.1880 (0.0154–0.4324) |

## Per-class rows and source-session counts for every fold

Rows in train reflect the same fold’s actual capped model-training dataframe. Validation rows are after the evaluator’s held-out-family removal. Test rows include all labels in the held-out test sessions; `known_test_rows` below records the subset represented in training and used for closed-set confusion. A source session is a CICIDS CSV capture file contributing rows for that class.

| Held-out family | Seed | Split | Class | Rows | Source sessions |
|---|---:|---|---|---:|---:|
| DosDDoS | 42 | train | BENIGN | 53997 | 4 |
| DosDDoS | 42 | train | Bot | 0 | 0 |
| DosDDoS | 42 | train | BruteForce | 537 | 1 |
| DosDDoS | 42 | train | DosDDoS | 0 | 0 |
| DosDDoS | 42 | train | PortScan | 5342 | 1 |
| DosDDoS | 42 | train | WebAttack | 124 | 1 |
| DosDDoS | 42 | validation | BENIGN | 25600 | 1 |
| DosDDoS | 42 | validation | Bot | 305 | 1 |
| DosDDoS | 42 | validation | BruteForce | 0 | 0 |
| DosDDoS | 42 | validation | DosDDoS | 0 | 0 |
| DosDDoS | 42 | validation | PortScan | 0 | 0 |
| DosDDoS | 42 | validation | WebAttack | 0 | 0 |
| DosDDoS | 42 | test | BENIGN | 74837 | 2 |
| DosDDoS | 42 | test | Bot | 0 | 0 |
| DosDDoS | 42 | test | BruteForce | 0 | 0 |
| DosDDoS | 42 | test | DosDDoS | 48296 | 2 |
| DosDDoS | 42 | test | PortScan | 0 | 0 |
| DosDDoS | 42 | test | WebAttack | 0 | 0 |
| DosDDoS | 101 | train | BENIGN | 59193 | 4 |
| DosDDoS | 101 | train | Bot | 123 | 1 |
| DosDDoS | 101 | train | BruteForce | 555 | 1 |
| DosDDoS | 101 | train | DosDDoS | 0 | 0 |
| DosDDoS | 101 | train | PortScan | 0 | 0 |
| DosDDoS | 101 | train | WebAttack | 129 | 1 |
| DosDDoS | 101 | validation | BENIGN | 17353 | 1 |
| DosDDoS | 101 | validation | Bot | 0 | 0 |
| DosDDoS | 101 | validation | BruteForce | 0 | 0 |
| DosDDoS | 101 | validation | DosDDoS | 0 | 0 |
| DosDDoS | 101 | validation | PortScan | 13730 | 1 |
| DosDDoS | 101 | validation | WebAttack | 0 | 0 |
| DosDDoS | 101 | test | BENIGN | 74837 | 2 |
| DosDDoS | 101 | test | Bot | 0 | 0 |
| DosDDoS | 101 | test | BruteForce | 0 | 0 |
| DosDDoS | 101 | test | DosDDoS | 48296 | 2 |
| DosDDoS | 101 | test | PortScan | 0 | 0 |
| DosDDoS | 101 | test | WebAttack | 0 | 0 |
| DosDDoS | 202 | train | BENIGN | 53997 | 4 |
| DosDDoS | 202 | train | Bot | 0 | 0 |
| DosDDoS | 202 | train | BruteForce | 537 | 1 |
| DosDDoS | 202 | train | DosDDoS | 0 | 0 |
| DosDDoS | 202 | train | PortScan | 5342 | 1 |
| DosDDoS | 202 | train | WebAttack | 124 | 1 |
| DosDDoS | 202 | validation | BENIGN | 25600 | 1 |
| DosDDoS | 202 | validation | Bot | 305 | 1 |
| DosDDoS | 202 | validation | BruteForce | 0 | 0 |
| DosDDoS | 202 | validation | DosDDoS | 0 | 0 |
| DosDDoS | 202 | validation | PortScan | 0 | 0 |
| DosDDoS | 202 | validation | WebAttack | 0 | 0 |
| DosDDoS | 202 | test | BENIGN | 74837 | 2 |
| DosDDoS | 202 | test | Bot | 0 | 0 |
| DosDDoS | 202 | test | BruteForce | 0 | 0 |
| DosDDoS | 202 | test | DosDDoS | 48296 | 2 |
| DosDDoS | 202 | test | PortScan | 0 | 0 |
| DosDDoS | 202 | test | WebAttack | 0 | 0 |
| DosDDoS | 303 | train | BENIGN | 52618 | 4 |
| DosDDoS | 303 | train | Bot | 157 | 1 |
| DosDDoS | 303 | train | BruteForce | 0 | 0 |
| DosDDoS | 303 | train | DosDDoS | 0 | 0 |
| DosDDoS | 303 | train | PortScan | 7060 | 1 |
| DosDDoS | 303 | train | WebAttack | 165 | 1 |
| DosDDoS | 303 | validation | BENIGN | 62059 | 1 |
| DosDDoS | 303 | validation | Bot | 0 | 0 |
| DosDDoS | 303 | validation | BruteForce | 1379 | 1 |
| DosDDoS | 303 | validation | DosDDoS | 0 | 0 |
| DosDDoS | 303 | validation | PortScan | 0 | 0 |
| DosDDoS | 303 | validation | WebAttack | 0 | 0 |
| DosDDoS | 303 | test | BENIGN | 74837 | 2 |
| DosDDoS | 303 | test | Bot | 0 | 0 |
| DosDDoS | 303 | test | BruteForce | 0 | 0 |
| DosDDoS | 303 | test | DosDDoS | 48296 | 2 |
| DosDDoS | 303 | test | PortScan | 0 | 0 |
| DosDDoS | 303 | test | WebAttack | 0 | 0 |
| DosDDoS | 404 | train | BENIGN | 53997 | 4 |
| DosDDoS | 404 | train | Bot | 0 | 0 |
| DosDDoS | 404 | train | BruteForce | 537 | 1 |
| DosDDoS | 404 | train | DosDDoS | 0 | 0 |
| DosDDoS | 404 | train | PortScan | 5342 | 1 |
| DosDDoS | 404 | train | WebAttack | 124 | 1 |
| DosDDoS | 404 | validation | BENIGN | 25600 | 1 |
| DosDDoS | 404 | validation | Bot | 305 | 1 |
| DosDDoS | 404 | validation | BruteForce | 0 | 0 |
| DosDDoS | 404 | validation | DosDDoS | 0 | 0 |
| DosDDoS | 404 | validation | PortScan | 0 | 0 |
| DosDDoS | 404 | validation | WebAttack | 0 | 0 |
| DosDDoS | 404 | test | BENIGN | 74837 | 2 |
| DosDDoS | 404 | test | Bot | 0 | 0 |
| DosDDoS | 404 | test | BruteForce | 0 | 0 |
| DosDDoS | 404 | test | DosDDoS | 48296 | 2 |
| DosDDoS | 404 | test | PortScan | 0 | 0 |
| DosDDoS | 404 | test | WebAttack | 0 | 0 |
| PortScan | 42 | train | BENIGN | 52203 | 5 |
| PortScan | 42 | train | Bot | 76 | 1 |
| PortScan | 42 | train | BruteForce | 346 | 1 |
| PortScan | 42 | train | DosDDoS | 7295 | 1 |
| PortScan | 42 | train | PortScan | 0 | 0 |
| PortScan | 42 | train | WebAttack | 80 | 1 |
| PortScan | 42 | validation | BENIGN | 13494 | 1 |
| PortScan | 42 | validation | Bot | 0 | 0 |
| PortScan | 42 | validation | BruteForce | 0 | 0 |
| PortScan | 42 | validation | DosDDoS | 19175 | 1 |
| PortScan | 42 | validation | PortScan | 0 | 0 |
| PortScan | 42 | validation | WebAttack | 0 | 0 |
| PortScan | 42 | test | BENIGN | 17353 | 1 |
| PortScan | 42 | test | Bot | 0 | 0 |
| PortScan | 42 | test | BruteForce | 0 | 0 |
| PortScan | 42 | test | DosDDoS | 0 | 0 |
| PortScan | 42 | test | PortScan | 13730 | 1 |
| PortScan | 42 | test | WebAttack | 0 | 0 |
| PortScan | 101 | train | BENIGN | 52203 | 5 |
| PortScan | 101 | train | Bot | 76 | 1 |
| PortScan | 101 | train | BruteForce | 346 | 1 |
| PortScan | 101 | train | DosDDoS | 7295 | 1 |
| PortScan | 101 | train | PortScan | 0 | 0 |
| PortScan | 101 | train | WebAttack | 80 | 1 |
| PortScan | 101 | validation | BENIGN | 13494 | 1 |
| PortScan | 101 | validation | Bot | 0 | 0 |
| PortScan | 101 | validation | BruteForce | 0 | 0 |
| PortScan | 101 | validation | DosDDoS | 19175 | 1 |
| PortScan | 101 | validation | PortScan | 0 | 0 |
| PortScan | 101 | validation | WebAttack | 0 | 0 |
| PortScan | 101 | test | BENIGN | 17353 | 1 |
| PortScan | 101 | test | Bot | 0 | 0 |
| PortScan | 101 | test | BruteForce | 0 | 0 |
| PortScan | 101 | test | DosDDoS | 0 | 0 |
| PortScan | 101 | test | PortScan | 13730 | 1 |
| PortScan | 101 | test | WebAttack | 0 | 0 |
| PortScan | 202 | train | BENIGN | 47206 | 5 |
| PortScan | 202 | train | Bot | 78 | 1 |
| PortScan | 202 | train | BruteForce | 351 | 1 |
| PortScan | 202 | train | DosDDoS | 12284 | 2 |
| PortScan | 202 | train | PortScan | 0 | 0 |
| PortScan | 202 | train | WebAttack | 81 | 1 |
| PortScan | 202 | validation | BENIGN | 36271 | 1 |
| PortScan | 202 | validation | Bot | 0 | 0 |
| PortScan | 202 | validation | BruteForce | 0 | 0 |
| PortScan | 202 | validation | DosDDoS | 0 | 0 |
| PortScan | 202 | validation | PortScan | 0 | 0 |
| PortScan | 202 | validation | WebAttack | 0 | 0 |
| PortScan | 202 | test | BENIGN | 17353 | 1 |
| PortScan | 202 | test | Bot | 0 | 0 |
| PortScan | 202 | test | BruteForce | 0 | 0 |
| PortScan | 202 | test | DosDDoS | 0 | 0 |
| PortScan | 202 | test | PortScan | 13730 | 1 |
| PortScan | 202 | test | WebAttack | 0 | 0 |
| PortScan | 303 | train | BENIGN | 53006 | 5 |
| PortScan | 303 | train | Bot | 101 | 1 |
| PortScan | 303 | train | BruteForce | 455 | 1 |
| PortScan | 303 | train | DosDDoS | 6332 | 1 |
| PortScan | 303 | train | PortScan | 0 | 0 |
| PortScan | 303 | train | WebAttack | 106 | 1 |
| PortScan | 303 | validation | BENIGN | 61343 | 1 |
| PortScan | 303 | validation | Bot | 0 | 0 |
| PortScan | 303 | validation | BruteForce | 0 | 0 |
| PortScan | 303 | validation | DosDDoS | 29121 | 1 |
| PortScan | 303 | validation | PortScan | 0 | 0 |
| PortScan | 303 | validation | WebAttack | 0 | 0 |
| PortScan | 303 | test | BENIGN | 17353 | 1 |
| PortScan | 303 | test | Bot | 0 | 0 |
| PortScan | 303 | test | BruteForce | 0 | 0 |
| PortScan | 303 | test | DosDDoS | 0 | 0 |
| PortScan | 303 | test | PortScan | 13730 | 1 |
| PortScan | 303 | test | WebAttack | 0 | 0 |
| PortScan | 404 | train | BENIGN | 47944 | 5 |
| PortScan | 404 | train | Bot | 74 | 1 |
| PortScan | 404 | train | BruteForce | 333 | 1 |
| PortScan | 404 | train | DosDDoS | 11649 | 2 |
| PortScan | 404 | train | PortScan | 0 | 0 |
| PortScan | 404 | train | WebAttack | 0 | 0 |
| PortScan | 404 | validation | BENIGN | 23103 | 1 |
| PortScan | 404 | validation | Bot | 0 | 0 |
| PortScan | 404 | validation | BruteForce | 0 | 0 |
| PortScan | 404 | validation | DosDDoS | 0 | 0 |
| PortScan | 404 | validation | PortScan | 0 | 0 |
| PortScan | 404 | validation | WebAttack | 320 | 1 |
| PortScan | 404 | test | BENIGN | 17353 | 1 |
| PortScan | 404 | test | Bot | 0 | 0 |
| PortScan | 404 | test | BruteForce | 0 | 0 |
| PortScan | 404 | test | DosDDoS | 0 | 0 |
| PortScan | 404 | test | PortScan | 13730 | 1 |
| PortScan | 404 | test | WebAttack | 0 | 0 |
| BruteForce | 42 | train | BENIGN | 47407 | 5 |
| BruteForce | 42 | train | Bot | 88 | 1 |
| BruteForce | 42 | train | BruteForce | 0 | 0 |
| BruteForce | 42 | train | DosDDoS | 8435 | 1 |
| BruteForce | 42 | train | PortScan | 3977 | 1 |
| BruteForce | 42 | train | WebAttack | 93 | 1 |
| BruteForce | 42 | validation | BENIGN | 13494 | 1 |
| BruteForce | 42 | validation | Bot | 0 | 0 |
| BruteForce | 42 | validation | BruteForce | 0 | 0 |
| BruteForce | 42 | validation | DosDDoS | 19175 | 1 |
| BruteForce | 42 | validation | PortScan | 0 | 0 |
| BruteForce | 42 | validation | WebAttack | 0 | 0 |
| BruteForce | 42 | test | BENIGN | 62059 | 1 |
| BruteForce | 42 | test | Bot | 0 | 0 |
| BruteForce | 42 | test | BruteForce | 1379 | 1 |
| BruteForce | 42 | test | DosDDoS | 0 | 0 |
| BruteForce | 42 | test | PortScan | 0 | 0 |
| BruteForce | 42 | test | WebAttack | 0 | 0 |
| BruteForce | 101 | train | BENIGN | 47407 | 5 |
| BruteForce | 101 | train | Bot | 88 | 1 |
| BruteForce | 101 | train | BruteForce | 0 | 0 |
| BruteForce | 101 | train | DosDDoS | 8435 | 1 |
| BruteForce | 101 | train | PortScan | 3977 | 1 |
| BruteForce | 101 | train | WebAttack | 93 | 1 |
| BruteForce | 101 | validation | BENIGN | 13494 | 1 |
| BruteForce | 101 | validation | Bot | 0 | 0 |
| BruteForce | 101 | validation | BruteForce | 0 | 0 |
| BruteForce | 101 | validation | DosDDoS | 19175 | 1 |
| BruteForce | 101 | validation | PortScan | 0 | 0 |
| BruteForce | 101 | validation | WebAttack | 0 | 0 |
| BruteForce | 101 | test | BENIGN | 62059 | 1 |
| BruteForce | 101 | test | Bot | 0 | 0 |
| BruteForce | 101 | test | BruteForce | 1379 | 1 |
| BruteForce | 101 | test | DosDDoS | 0 | 0 |
| BruteForce | 101 | test | PortScan | 0 | 0 |
| BruteForce | 101 | test | WebAttack | 0 | 0 |
| BruteForce | 202 | train | BENIGN | 42512 | 5 |
| BruteForce | 202 | train | Bot | 0 | 0 |
| BruteForce | 202 | train | BruteForce | 0 | 0 |
| BruteForce | 202 | train | DosDDoS | 13547 | 2 |
| BruteForce | 202 | train | PortScan | 3851 | 1 |
| BruteForce | 202 | train | WebAttack | 90 | 1 |
| BruteForce | 202 | validation | BENIGN | 25600 | 1 |
| BruteForce | 202 | validation | Bot | 305 | 1 |
| BruteForce | 202 | validation | BruteForce | 0 | 0 |
| BruteForce | 202 | validation | DosDDoS | 0 | 0 |
| BruteForce | 202 | validation | PortScan | 0 | 0 |
| BruteForce | 202 | validation | WebAttack | 0 | 0 |
| BruteForce | 202 | test | BENIGN | 62059 | 1 |
| BruteForce | 202 | test | Bot | 0 | 0 |
| BruteForce | 202 | test | BruteForce | 1379 | 1 |
| BruteForce | 202 | test | DosDDoS | 0 | 0 |
| BruteForce | 202 | test | PortScan | 0 | 0 |
| BruteForce | 202 | test | WebAttack | 0 | 0 |
| BruteForce | 303 | train | BENIGN | 46530 | 5 |
| BruteForce | 303 | train | Bot | 122 | 1 |
| BruteForce | 303 | train | BruteForce | 0 | 0 |
| BruteForce | 303 | train | DosDDoS | 7703 | 1 |
| BruteForce | 303 | train | PortScan | 5516 | 1 |
| BruteForce | 303 | train | WebAttack | 129 | 1 |
| BruteForce | 303 | validation | BENIGN | 61343 | 1 |
| BruteForce | 303 | validation | Bot | 0 | 0 |
| BruteForce | 303 | validation | BruteForce | 0 | 0 |
| BruteForce | 303 | validation | DosDDoS | 29121 | 1 |
| BruteForce | 303 | validation | PortScan | 0 | 0 |
| BruteForce | 303 | validation | WebAttack | 0 | 0 |
| BruteForce | 303 | test | BENIGN | 62059 | 1 |
| BruteForce | 303 | test | Bot | 0 | 0 |
| BruteForce | 303 | test | BruteForce | 1379 | 1 |
| BruteForce | 303 | test | DosDDoS | 0 | 0 |
| BruteForce | 303 | test | PortScan | 0 | 0 |
| BruteForce | 303 | test | WebAttack | 0 | 0 |
| BruteForce | 404 | train | BENIGN | 41532 | 5 |
| BruteForce | 404 | train | Bot | 90 | 1 |
| BruteForce | 404 | train | BruteForce | 0 | 0 |
| BruteForce | 404 | train | DosDDoS | 14237 | 2 |
| BruteForce | 404 | train | PortScan | 4047 | 1 |
| BruteForce | 404 | train | WebAttack | 94 | 1 |
| BruteForce | 404 | validation | BENIGN | 36271 | 1 |
| BruteForce | 404 | validation | Bot | 0 | 0 |
| BruteForce | 404 | validation | BruteForce | 0 | 0 |
| BruteForce | 404 | validation | DosDDoS | 0 | 0 |
| BruteForce | 404 | validation | PortScan | 0 | 0 |
| BruteForce | 404 | validation | WebAttack | 0 | 0 |
| BruteForce | 404 | test | BENIGN | 62059 | 1 |
| BruteForce | 404 | test | Bot | 0 | 0 |
| BruteForce | 404 | test | BruteForce | 1379 | 1 |
| BruteForce | 404 | test | DosDDoS | 0 | 0 |
| BruteForce | 404 | test | PortScan | 0 | 0 |
| BruteForce | 404 | test | WebAttack | 0 | 0 |
| WebAttack | 42 | train | BENIGN | 49189 | 5 |
| WebAttack | 42 | train | Bot | 74 | 1 |
| WebAttack | 42 | train | BruteForce | 335 | 1 |
| WebAttack | 42 | train | DosDDoS | 7069 | 1 |
| WebAttack | 42 | train | PortScan | 3333 | 1 |
| WebAttack | 42 | train | WebAttack | 0 | 0 |
| WebAttack | 42 | validation | BENIGN | 13494 | 1 |
| WebAttack | 42 | validation | Bot | 0 | 0 |
| WebAttack | 42 | validation | BruteForce | 0 | 0 |
| WebAttack | 42 | validation | DosDDoS | 19175 | 1 |
| WebAttack | 42 | validation | PortScan | 0 | 0 |
| WebAttack | 42 | validation | WebAttack | 0 | 0 |
| WebAttack | 42 | test | BENIGN | 23103 | 1 |
| WebAttack | 42 | test | Bot | 0 | 0 |
| WebAttack | 42 | test | BruteForce | 0 | 0 |
| WebAttack | 42 | test | DosDDoS | 0 | 0 |
| WebAttack | 42 | test | PortScan | 0 | 0 |
| WebAttack | 42 | test | WebAttack | 320 | 1 |
| WebAttack | 101 | train | BENIGN | 49189 | 5 |
| WebAttack | 101 | train | Bot | 74 | 1 |
| WebAttack | 101 | train | BruteForce | 335 | 1 |
| WebAttack | 101 | train | DosDDoS | 7069 | 1 |
| WebAttack | 101 | train | PortScan | 3333 | 1 |
| WebAttack | 101 | train | WebAttack | 0 | 0 |
| WebAttack | 101 | validation | BENIGN | 13494 | 1 |
| WebAttack | 101 | validation | Bot | 0 | 0 |
| WebAttack | 101 | validation | BruteForce | 0 | 0 |
| WebAttack | 101 | validation | DosDDoS | 19175 | 1 |
| WebAttack | 101 | validation | PortScan | 0 | 0 |
| WebAttack | 101 | validation | WebAttack | 0 | 0 |
| WebAttack | 101 | test | BENIGN | 23103 | 1 |
| WebAttack | 101 | test | Bot | 0 | 0 |
| WebAttack | 101 | test | BruteForce | 0 | 0 |
| WebAttack | 101 | test | DosDDoS | 0 | 0 |
| WebAttack | 101 | test | PortScan | 0 | 0 |
| WebAttack | 101 | test | WebAttack | 320 | 1 |
| WebAttack | 202 | train | BENIGN | 45018 | 5 |
| WebAttack | 202 | train | Bot | 0 | 0 |
| WebAttack | 202 | train | BruteForce | 326 | 1 |
| WebAttack | 202 | train | DosDDoS | 11412 | 2 |
| WebAttack | 202 | train | PortScan | 3244 | 1 |
| WebAttack | 202 | train | WebAttack | 0 | 0 |
| WebAttack | 202 | validation | BENIGN | 25600 | 1 |
| WebAttack | 202 | validation | Bot | 305 | 1 |
| WebAttack | 202 | validation | BruteForce | 0 | 0 |
| WebAttack | 202 | validation | DosDDoS | 0 | 0 |
| WebAttack | 202 | validation | PortScan | 0 | 0 |
| WebAttack | 202 | validation | WebAttack | 0 | 0 |
| WebAttack | 202 | test | BENIGN | 23103 | 1 |
| WebAttack | 202 | test | Bot | 0 | 0 |
| WebAttack | 202 | test | BruteForce | 0 | 0 |
| WebAttack | 202 | test | DosDDoS | 0 | 0 |
| WebAttack | 202 | test | PortScan | 0 | 0 |
| WebAttack | 202 | test | WebAttack | 320 | 1 |
| WebAttack | 303 | train | BENIGN | 49041 | 5 |
| WebAttack | 303 | train | Bot | 97 | 1 |
| WebAttack | 303 | train | BruteForce | 437 | 1 |
| WebAttack | 303 | train | DosDDoS | 6075 | 1 |
| WebAttack | 303 | train | PortScan | 4350 | 1 |
| WebAttack | 303 | train | WebAttack | 0 | 0 |
| WebAttack | 303 | validation | BENIGN | 61343 | 1 |
| WebAttack | 303 | validation | Bot | 0 | 0 |
| WebAttack | 303 | validation | BruteForce | 0 | 0 |
| WebAttack | 303 | validation | DosDDoS | 29121 | 1 |
| WebAttack | 303 | validation | PortScan | 0 | 0 |
| WebAttack | 303 | validation | WebAttack | 0 | 0 |
| WebAttack | 303 | test | BENIGN | 23103 | 1 |
| WebAttack | 303 | test | Bot | 0 | 0 |
| WebAttack | 303 | test | BruteForce | 0 | 0 |
| WebAttack | 303 | test | DosDDoS | 0 | 0 |
| WebAttack | 303 | test | PortScan | 0 | 0 |
| WebAttack | 303 | test | WebAttack | 320 | 1 |
| WebAttack | 404 | train | BENIGN | 44305 | 5 |
| WebAttack | 404 | train | Bot | 75 | 1 |
| WebAttack | 404 | train | BruteForce | 340 | 1 |
| WebAttack | 404 | train | DosDDoS | 11898 | 2 |
| WebAttack | 404 | train | PortScan | 3382 | 1 |
| WebAttack | 404 | train | WebAttack | 0 | 0 |
| WebAttack | 404 | validation | BENIGN | 36271 | 1 |
| WebAttack | 404 | validation | Bot | 0 | 0 |
| WebAttack | 404 | validation | BruteForce | 0 | 0 |
| WebAttack | 404 | validation | DosDDoS | 0 | 0 |
| WebAttack | 404 | validation | PortScan | 0 | 0 |
| WebAttack | 404 | validation | WebAttack | 0 | 0 |
| WebAttack | 404 | test | BENIGN | 23103 | 1 |
| WebAttack | 404 | test | Bot | 0 | 0 |
| WebAttack | 404 | test | BruteForce | 0 | 0 |
| WebAttack | 404 | test | DosDDoS | 0 | 0 |
| WebAttack | 404 | test | PortScan | 0 | 0 |
| WebAttack | 404 | test | WebAttack | 320 | 1 |
| Bot | 42 | train | BENIGN | 49076 | 5 |
| Bot | 42 | train | Bot | 0 | 0 |
| Bot | 42 | train | BruteForce | 338 | 1 |
| Bot | 42 | train | DosDDoS | 7141 | 1 |
| Bot | 42 | train | PortScan | 3367 | 1 |
| Bot | 42 | train | WebAttack | 78 | 1 |
| Bot | 42 | validation | BENIGN | 13494 | 1 |
| Bot | 42 | validation | Bot | 0 | 0 |
| Bot | 42 | validation | BruteForce | 0 | 0 |
| Bot | 42 | validation | DosDDoS | 19175 | 1 |
| Bot | 42 | validation | PortScan | 0 | 0 |
| Bot | 42 | validation | WebAttack | 0 | 0 |
| Bot | 42 | test | BENIGN | 25600 | 1 |
| Bot | 42 | test | Bot | 305 | 1 |
| Bot | 42 | test | BruteForce | 0 | 0 |
| Bot | 42 | test | DosDDoS | 0 | 0 |
| Bot | 42 | test | PortScan | 0 | 0 |
| Bot | 42 | test | WebAttack | 0 | 0 |
| Bot | 101 | train | BENIGN | 49076 | 5 |
| Bot | 101 | train | Bot | 0 | 0 |
| Bot | 101 | train | BruteForce | 338 | 1 |
| Bot | 101 | train | DosDDoS | 7141 | 1 |
| Bot | 101 | train | PortScan | 3367 | 1 |
| Bot | 101 | train | WebAttack | 78 | 1 |
| Bot | 101 | validation | BENIGN | 13494 | 1 |
| Bot | 101 | validation | Bot | 0 | 0 |
| Bot | 101 | validation | BruteForce | 0 | 0 |
| Bot | 101 | validation | DosDDoS | 19175 | 1 |
| Bot | 101 | validation | PortScan | 0 | 0 |
| Bot | 101 | validation | WebAttack | 0 | 0 |
| Bot | 101 | test | BENIGN | 25600 | 1 |
| Bot | 101 | test | Bot | 305 | 1 |
| Bot | 101 | test | BruteForce | 0 | 0 |
| Bot | 101 | test | DosDDoS | 0 | 0 |
| Bot | 101 | test | PortScan | 0 | 0 |
| Bot | 101 | test | WebAttack | 0 | 0 |
| Bot | 202 | train | BENIGN | 44140 | 5 |
| Bot | 202 | train | Bot | 0 | 0 |
| Bot | 202 | train | BruteForce | 343 | 1 |
| Bot | 202 | train | DosDDoS | 12020 | 2 |
| Bot | 202 | train | PortScan | 3417 | 1 |
| Bot | 202 | train | WebAttack | 80 | 1 |
| Bot | 202 | validation | BENIGN | 36271 | 1 |
| Bot | 202 | validation | Bot | 0 | 0 |
| Bot | 202 | validation | BruteForce | 0 | 0 |
| Bot | 202 | validation | DosDDoS | 0 | 0 |
| Bot | 202 | validation | PortScan | 0 | 0 |
| Bot | 202 | validation | WebAttack | 0 | 0 |
| Bot | 202 | test | BENIGN | 25600 | 1 |
| Bot | 202 | test | Bot | 305 | 1 |
| Bot | 202 | test | BruteForce | 0 | 0 |
| Bot | 202 | test | DosDDoS | 0 | 0 |
| Bot | 202 | test | PortScan | 0 | 0 |
| Bot | 202 | test | WebAttack | 0 | 0 |
| Bot | 303 | train | BENIGN | 48890 | 5 |
| Bot | 303 | train | Bot | 0 | 0 |
| Bot | 303 | train | BruteForce | 443 | 1 |
| Bot | 303 | train | DosDDoS | 6156 | 1 |
| Bot | 303 | train | PortScan | 4408 | 1 |
| Bot | 303 | train | WebAttack | 103 | 1 |
| Bot | 303 | validation | BENIGN | 61343 | 1 |
| Bot | 303 | validation | Bot | 0 | 0 |
| Bot | 303 | validation | BruteForce | 0 | 0 |
| Bot | 303 | validation | DosDDoS | 29121 | 1 |
| Bot | 303 | validation | PortScan | 0 | 0 |
| Bot | 303 | validation | WebAttack | 0 | 0 |
| Bot | 303 | test | BENIGN | 25600 | 1 |
| Bot | 303 | test | Bot | 305 | 1 |
| Bot | 303 | test | BruteForce | 0 | 0 |
| Bot | 303 | test | DosDDoS | 0 | 0 |
| Bot | 303 | test | PortScan | 0 | 0 |
| Bot | 303 | test | WebAttack | 0 | 0 |
| Bot | 404 | train | BENIGN | 45018 | 5 |
| Bot | 404 | train | Bot | 0 | 0 |
| Bot | 404 | train | BruteForce | 326 | 1 |
| Bot | 404 | train | DosDDoS | 11412 | 2 |
| Bot | 404 | train | PortScan | 3244 | 1 |
| Bot | 404 | train | WebAttack | 0 | 0 |
| Bot | 404 | validation | BENIGN | 23103 | 1 |
| Bot | 404 | validation | Bot | 0 | 0 |
| Bot | 404 | validation | BruteForce | 0 | 0 |
| Bot | 404 | validation | DosDDoS | 0 | 0 |
| Bot | 404 | validation | PortScan | 0 | 0 |
| Bot | 404 | validation | WebAttack | 320 | 1 |
| Bot | 404 | test | BENIGN | 25600 | 1 |
| Bot | 404 | test | Bot | 305 | 1 |
| Bot | 404 | test | BruteForce | 0 | 0 |
| Bot | 404 | test | DosDDoS | 0 | 0 |
| Bot | 404 | test | PortScan | 0 | 0 |
| Bot | 404 | test | WebAttack | 0 | 0 |

A target family with a single held-out source session has one capture context for its unknown-family test, regardless of row count. This makes seed-bootstrap intervals insufficient to estimate across-session uncertainty. Treat fewer than three independent capture sessions as too little support for a reliable cross-session class estimate; all four weak targets are below that threshold, with exactly one held-out source file each. Bot and WebAttack additionally have only 305 and 320 unknown rows per seed. PortScan has many rows but still only one held-out capture session.

## Known-class confusion matrices

Matrices use only known test rows whose label was present in that fold’s training classes. Rows are actual class; columns are predicted class. The held-out family is excluded from these closed-set matrices and assessed separately by open-set rejection. Rows/columns use the fold’s training label encoder order.

### Held out DosDDoS — seed 42

Known test rows: 74837; excluded test rows with labels absent from training: 0; held-out unknown rows: 48296.

| Actual \ Predicted | BENIGN | BruteForce | PortScan | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 74797 | 6 | 27 | 7 |
| BruteForce | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out DosDDoS — seed 101

Known test rows: 74837; excluded test rows with labels absent from training: 0; held-out unknown rows: 48296.

| Actual \ Predicted | BENIGN | Bot | BruteForce | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 74704 | 128 | 3 | 2 |
| Bot | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out DosDDoS — seed 202

Known test rows: 74837; excluded test rows with labels absent from training: 0; held-out unknown rows: 48296.

| Actual \ Predicted | BENIGN | BruteForce | PortScan | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 74803 | 1 | 28 | 5 |
| BruteForce | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out DosDDoS — seed 303

Known test rows: 74837; excluded test rows with labels absent from training: 0; held-out unknown rows: 48296.

| Actual \ Predicted | BENIGN | Bot | PortScan | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 74770 | 50 | 0 | 17 |
| Bot | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out DosDDoS — seed 404

Known test rows: 74837; excluded test rows with labels absent from training: 0; held-out unknown rows: 48296.

| Actual \ Predicted | BENIGN | BruteForce | PortScan | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 74831 | 4 | 1 | 1 |
| BruteForce | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out PortScan — seed 42

Known test rows: 17353; excluded test rows with labels absent from training: 0; held-out unknown rows: 13730.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 17254 | 91 | 1 | 7 | 0 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out PortScan — seed 101

Known test rows: 17353; excluded test rows with labels absent from training: 0; held-out unknown rows: 13730.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 17222 | 114 | 10 | 6 | 1 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out PortScan — seed 202

Known test rows: 17353; excluded test rows with labels absent from training: 0; held-out unknown rows: 13730.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 17265 | 85 | 0 | 2 | 1 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out PortScan — seed 303

Known test rows: 17353; excluded test rows with labels absent from training: 0; held-out unknown rows: 13730.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 17223 | 112 | 13 | 4 | 1 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out PortScan — seed 404

Known test rows: 17353; excluded test rows with labels absent from training: 0; held-out unknown rows: 13730.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS |
|---|---:|---:|---:|---:|
| BENIGN | 17256 | 94 | 1 | 2 |
| Bot | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 |

### Held out BruteForce — seed 42

Known test rows: 62059; excluded test rows with labels absent from training: 0; held-out unknown rows: 1379.

| Actual \ Predicted | BENIGN | Bot | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 57881 | 3421 | 571 | 13 | 173 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out BruteForce — seed 101

Known test rows: 62059; excluded test rows with labels absent from training: 0; held-out unknown rows: 1379.

| Actual \ Predicted | BENIGN | Bot | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 60846 | 420 | 642 | 10 | 141 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out BruteForce — seed 202

Known test rows: 62059; excluded test rows with labels absent from training: 0; held-out unknown rows: 1379.

| Actual \ Predicted | BENIGN | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|
| BENIGN | 61928 | 101 | 10 | 20 |
| DosDDoS | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 |

### Held out BruteForce — seed 303

Known test rows: 62059; excluded test rows with labels absent from training: 0; held-out unknown rows: 1379.

| Actual \ Predicted | BENIGN | Bot | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 61675 | 104 | 5 | 26 | 249 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out BruteForce — seed 404

Known test rows: 62059; excluded test rows with labels absent from training: 0; held-out unknown rows: 1379.

| Actual \ Predicted | BENIGN | Bot | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 61476 | 204 | 301 | 7 | 71 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out WebAttack — seed 42

Known test rows: 23103; excluded test rows with labels absent from training: 0; held-out unknown rows: 320.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|---:|
| BENIGN | 22965 | 95 | 5 | 33 | 5 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |

### Held out WebAttack — seed 101

Known test rows: 23103; excluded test rows with labels absent from training: 0; held-out unknown rows: 320.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|---:|
| BENIGN | 22234 | 805 | 2 | 42 | 20 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |

### Held out WebAttack — seed 202

Known test rows: 23103; excluded test rows with labels absent from training: 0; held-out unknown rows: 320.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|
| BENIGN | 23084 | 0 | 16 | 3 |
| BruteForce | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |

### Held out WebAttack — seed 303

Known test rows: 23103; excluded test rows with labels absent from training: 0; held-out unknown rows: 320.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|---:|
| BENIGN | 23053 | 46 | 0 | 1 | 3 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |

### Held out WebAttack — seed 404

Known test rows: 23103; excluded test rows with labels absent from training: 0; held-out unknown rows: 320.

| Actual \ Predicted | BENIGN | Bot | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|---:|
| BENIGN | 23003 | 30 | 36 | 34 | 0 |
| Bot | 0 | 0 | 0 | 0 | 0 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |

### Held out Bot — seed 42

Known test rows: 25600; excluded test rows with labels absent from training: 0; held-out unknown rows: 305.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 25543 | 0 | 37 | 1 | 19 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out Bot — seed 101

Known test rows: 25600; excluded test rows with labels absent from training: 0; held-out unknown rows: 305.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 25519 | 2 | 50 | 0 | 29 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out Bot — seed 202

Known test rows: 25600; excluded test rows with labels absent from training: 0; held-out unknown rows: 305.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 25558 | 0 | 35 | 0 | 7 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out Bot — seed 303

Known test rows: 25600; excluded test rows with labels absent from training: 0; held-out unknown rows: 305.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan | WebAttack |
|---|---:|---:|---:|---:|---:|
| BENIGN | 25559 | 4 | 10 | 2 | 25 |
| BruteForce | 0 | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 | 0 |
| WebAttack | 0 | 0 | 0 | 0 | 0 |

### Held out Bot — seed 404

Known test rows: 25600; excluded test rows with labels absent from training: 0; held-out unknown rows: 305.

| Actual \ Predicted | BENIGN | BruteForce | DosDDoS | PortScan |
|---|---:|---:|---:|---:|
| BENIGN | 25587 | 0 | 10 | 3 |
| BruteForce | 0 | 0 | 0 | 0 |
| DosDDoS | 0 | 0 | 0 | 0 |
| PortScan | 0 | 0 | 0 | 0 |

## Confusion destinations for weak known classes

For each weak class, this summarizes row-normalized confusion on known-only test folds where that class was represented in training and had test support. Each eligible fold contributes one normalized row, so larger folds do not dominate; the number of eligible fold-seed matrices is shown. This is descriptive model error analysis, not independent capture-session replication.

| Class | Eligible fold-seed matrices | Largest confusion destinations (mean row rate) |
|---|---:|---|
| Bot | 0 | No known-only test folds with supported rows |
| WebAttack | 0 | No known-only test folds with supported rows |
| BruteForce | 0 | No known-only test folds with supported rows |
| PortScan | 0 | No known-only test folds with supported rows |

## Held-out feature separation from BENIGN

For every model input feature, the table gives raw one-vs-rest ROC AUC for target-vs-BENIGN rows in that family’s fixed held-out test sessions, plus orientation-independent separation `max(AUC, 1−AUC)`. Values near 0.5 indicate little univariate separation; higher values indicate an association in this held-out sample, not a causal feature or a valid selection result. Source-session composition can confound these descriptive AUCs. All available model features are listed.

### Bot

Rows: 25905 total; 305 target and 25600 BENIGN. Target test sessions: Friday-WorkingHours-Morning.pcap_ISCX.csv.

| Feature | Raw AUC (target=1) | Separation AUC | Direction | Constant in test? |
|---|---:|---:|---|---|
| is_well_known_port | 0.0889 | 0.9111 | lower in target | no |
| is_registered_port | 0.8508 | 0.8508 | higher in target | no |
| Average Packet Size | 0.2066 | 0.7934 | lower in target | no |
| Packet Length Mean | 0.2093 | 0.7907 | lower in target | no |
| Avg Bwd Segment Size | 0.2520 | 0.7480 | lower in target | no |
| Bwd Packet Length Mean | 0.2520 | 0.7480 | lower in target | no |
| Init_Win_bytes_backward | 0.7445 | 0.7445 | higher in target | no |
| Fwd Packet Length Min | 0.2764 | 0.7236 | lower in target | no |
| Min Packet Length | 0.2796 | 0.7204 | lower in target | no |
| Init_Win_bytes_forward | 0.7091 | 0.7091 | higher in target | no |
| Subflow Bwd Bytes | 0.3118 | 0.6882 | lower in target | no |
| Total Length of Bwd Packets | 0.3118 | 0.6882 | lower in target | no |
| PSH Flag Count | 0.6867 | 0.6867 | higher in target | no |
| Subflow Fwd Bytes | 0.3154 | 0.6846 | lower in target | no |
| Total Length of Fwd Packets | 0.3154 | 0.6846 | lower in target | no |
| Avg Fwd Segment Size | 0.3246 | 0.6754 | lower in target | no |
| Fwd Packet Length Mean | 0.3246 | 0.6754 | lower in target | no |
| Bwd Packets/s | 0.6669 | 0.6669 | higher in target | no |
| Fwd Packet Length Max | 0.3356 | 0.6644 | lower in target | no |
| Max Packet Length | 0.3399 | 0.6601 | lower in target | no |
| Packet Length Std | 0.3417 | 0.6583 | lower in target | no |
| Packet Length Variance | 0.3417 | 0.6583 | lower in target | no |
| Bwd IAT Min | 0.6550 | 0.6550 | higher in target | no |
| min_seg_size_forward | 0.3525 | 0.6475 | lower in target | no |
| Bwd Packet Length Max | 0.3542 | 0.6458 | lower in target | no |
| Flow IAT Min | 0.6417 | 0.6417 | higher in target | no |
| URG Flag Count | 0.6379 | 0.6379 | higher in target | no |
| act_data_pkt_fwd | 0.3631 | 0.6369 | lower in target | no |
| Bwd IAT Std | 0.6345 | 0.6345 | higher in target | no |
| Bwd Packet Length Min | 0.3726 | 0.6274 | lower in target | no |
| Flow IAT Mean | 0.4001 | 0.5999 | lower in target | no |
| Fwd Packets/s | 0.5981 | 0.5981 | higher in target | no |
| Flow Packets/s | 0.5974 | 0.5974 | higher in target | no |
| Idle Max | 0.4097 | 0.5903 | lower in target | no |
| Idle Mean | 0.4097 | 0.5903 | lower in target | no |
| Idle Min | 0.4097 | 0.5903 | lower in target | no |
| Active Max | 0.4099 | 0.5901 | lower in target | no |
| Active Mean | 0.4099 | 0.5901 | lower in target | no |
| Active Min | 0.4099 | 0.5901 | lower in target | no |
| fwd_bwd_byte_ratio | 0.5840 | 0.5840 | higher in target | no |
| Bwd IAT Mean | 0.5809 | 0.5809 | higher in target | no |
| Fwd IAT Std | 0.5729 | 0.5729 | higher in target | no |
| Subflow Bwd Packets | 0.5698 | 0.5698 | higher in target | no |
| Total Backward Packets | 0.5698 | 0.5698 | higher in target | no |
| Bwd IAT Max | 0.5687 | 0.5687 | higher in target | no |
| Bwd IAT Total | 0.5632 | 0.5632 | higher in target | no |
| Fwd IAT Min | 0.5620 | 0.5620 | higher in target | no |
| ACK Flag Count | 0.5603 | 0.5603 | higher in target | no |
| is_ephemeral_port | 0.5603 | 0.5603 | higher in target | no |
| Flow Duration | 0.4440 | 0.5560 | lower in target | no |
| Idle Std | 0.4470 | 0.5530 | lower in target | no |
| Active Std | 0.4472 | 0.5528 | lower in target | no |
| Flow IAT Max | 0.4486 | 0.5514 | lower in target | no |
| Fwd Header Length | 0.4714 | 0.5286 | lower in target | no |
| Fwd Header Length.1 | 0.4714 | 0.5286 | lower in target | no |
| Fwd PSH Flags | 0.4725 | 0.5275 | lower in target | no |
| SYN Flag Count | 0.4725 | 0.5275 | lower in target | no |
| Flow Bytes/s | 0.5230 | 0.5230 | higher in target | no |
| iat_cv | 0.4847 | 0.5153 | lower in target | no |
| Bwd Header Length | 0.4878 | 0.5122 | lower in target | no |
| Bwd Packet Length Std | 0.5067 | 0.5067 | higher in target | no |
| Flow IAT Std | 0.4937 | 0.5063 | lower in target | no |
| Subflow Fwd Packets | 0.4940 | 0.5060 | lower in target | no |
| Total Fwd Packets | 0.4940 | 0.5060 | lower in target | no |
| Fwd IAT Mean | 0.5045 | 0.5045 | higher in target | no |
| Fwd IAT Total | 0.4959 | 0.5041 | lower in target | no |
| FIN Flag Count | 0.4963 | 0.5037 | lower in target | no |
| Fwd IAT Max | 0.5009 | 0.5009 | higher in target | no |
| ECE Flag Count | 0.4998 | 0.5002 | lower in target | no |
| RST Flag Count | 0.4998 | 0.5002 | lower in target | no |
| Down/Up Ratio | 0.5001 | 0.5001 | higher in target | no |
| Fwd Packet Length Std | 0.5001 | 0.5001 | higher in target | no |
| Bwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd PSH Flags | 0.5000 | 0.5000 | higher in target | yes |
| Bwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| CWE Flag Count | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| distinct_dst_ports_1m | 0.5000 | 0.5000 | higher in target | yes |
| flow_inter_arrival_variance | 0.5000 | 0.5000 | higher in target | yes |
| mean_bytes_per_flow | 0.5000 | 0.5000 | higher in target | yes |
| syn_to_ack_ratio | 0.5000 | 0.5000 | higher in target | yes |
| win_flow_rate_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_syn_only_ratio_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ips_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ports_60s | 0.5000 | 0.5000 | higher in target | yes |

### WebAttack

Rows: 23423 total; 320 target and 23103 BENIGN. Target test sessions: Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.

| Feature | Raw AUC (target=1) | Separation AUC | Direction | Constant in test? |
|---|---:|---:|---|---|
| Init_Win_bytes_backward | 0.9324 | 0.9324 | higher in target | no |
| Flow Bytes/s | 0.0744 | 0.9256 | lower in target | no |
| fwd_bwd_byte_ratio | 0.0970 | 0.9030 | lower in target | no |
| Init_Win_bytes_forward | 0.8948 | 0.8948 | higher in target | no |
| Max Packet Length | 0.1077 | 0.8923 | lower in target | no |
| Average Packet Size | 0.1091 | 0.8909 | lower in target | no |
| Packet Length Mean | 0.1111 | 0.8889 | lower in target | no |
| Fwd Packet Length Max | 0.1162 | 0.8838 | lower in target | no |
| Subflow Fwd Bytes | 0.1164 | 0.8836 | lower in target | no |
| Total Length of Fwd Packets | 0.1164 | 0.8836 | lower in target | no |
| Avg Fwd Segment Size | 0.1196 | 0.8804 | lower in target | no |
| Fwd Packet Length Mean | 0.1196 | 0.8804 | lower in target | no |
| Avg Bwd Segment Size | 0.1517 | 0.8483 | lower in target | no |
| Bwd Packet Length Mean | 0.1517 | 0.8483 | lower in target | no |
| Fwd IAT Min | 0.8448 | 0.8448 | higher in target | no |
| Bwd Packet Length Max | 0.1554 | 0.8446 | lower in target | no |
| Subflow Bwd Bytes | 0.1597 | 0.8403 | lower in target | no |
| Total Length of Bwd Packets | 0.1597 | 0.8403 | lower in target | no |
| PSH Flag Count | 0.8397 | 0.8397 | higher in target | no |
| Fwd IAT Std | 0.8308 | 0.8308 | higher in target | no |
| Packet Length Std | 0.1705 | 0.8295 | lower in target | no |
| Packet Length Variance | 0.1705 | 0.8295 | lower in target | no |
| Flow IAT Mean | 0.8144 | 0.8144 | higher in target | no |
| Fwd Packet Length Min | 0.1865 | 0.8135 | lower in target | no |
| Min Packet Length | 0.1883 | 0.8117 | lower in target | no |
| Fwd IAT Mean | 0.8104 | 0.8104 | higher in target | no |
| Flow Packets/s | 0.1957 | 0.8043 | lower in target | no |
| Flow IAT Std | 0.8021 | 0.8021 | higher in target | no |
| Fwd Packets/s | 0.2062 | 0.7938 | lower in target | no |
| Bwd Packet Length Min | 0.2078 | 0.7922 | lower in target | no |
| act_data_pkt_fwd | 0.2083 | 0.7917 | lower in target | no |
| Down/Up Ratio | 0.2129 | 0.7871 | lower in target | no |
| Fwd IAT Max | 0.7752 | 0.7752 | higher in target | no |
| Fwd IAT Total | 0.7702 | 0.7702 | higher in target | no |
| min_seg_size_forward | 0.7658 | 0.7658 | higher in target | no |
| Flow IAT Max | 0.7636 | 0.7636 | higher in target | no |
| Flow Duration | 0.7582 | 0.7582 | higher in target | no |
| Bwd Packets/s | 0.2510 | 0.7490 | lower in target | no |
| Bwd IAT Min | 0.2602 | 0.7398 | lower in target | no |
| Bwd IAT Max | 0.2604 | 0.7396 | lower in target | no |
| Bwd IAT Mean | 0.2615 | 0.7385 | lower in target | no |
| Bwd IAT Total | 0.2623 | 0.7377 | lower in target | no |
| Fwd Header Length | 0.7224 | 0.7224 | higher in target | no |
| Fwd Header Length.1 | 0.7224 | 0.7224 | higher in target | no |
| iat_cv | 0.7210 | 0.7210 | higher in target | no |
| Flow IAT Min | 0.7199 | 0.7199 | higher in target | no |
| Subflow Bwd Packets | 0.3125 | 0.6875 | lower in target | no |
| Total Backward Packets | 0.3125 | 0.6875 | lower in target | no |
| Subflow Fwd Packets | 0.6513 | 0.6513 | higher in target | no |
| Total Fwd Packets | 0.6513 | 0.6513 | higher in target | no |
| Fwd Packet Length Std | 0.3808 | 0.6192 | lower in target | no |
| ACK Flag Count | 0.4000 | 0.6000 | lower in target | no |
| is_well_known_port | 0.5933 | 0.5933 | higher in target | no |
| Bwd Packet Length Std | 0.4088 | 0.5912 | lower in target | no |
| Idle Max | 0.4094 | 0.5906 | lower in target | no |
| Idle Mean | 0.4094 | 0.5906 | lower in target | no |
| Idle Min | 0.4094 | 0.5906 | lower in target | no |
| Active Max | 0.4099 | 0.5901 | lower in target | no |
| Active Mean | 0.4099 | 0.5901 | lower in target | no |
| Active Min | 0.4099 | 0.5901 | lower in target | no |
| Bwd IAT Std | 0.4119 | 0.5881 | lower in target | no |
| is_ephemeral_port | 0.4405 | 0.5595 | lower in target | no |
| Idle Std | 0.4435 | 0.5565 | lower in target | no |
| Active Std | 0.4438 | 0.5562 | lower in target | no |
| is_registered_port | 0.4662 | 0.5338 | lower in target | no |
| URG Flag Count | 0.4712 | 0.5288 | lower in target | no |
| Fwd PSH Flags | 0.4768 | 0.5232 | lower in target | no |
| SYN Flag Count | 0.4768 | 0.5232 | lower in target | no |
| Bwd Header Length | 0.5161 | 0.5161 | higher in target | no |
| FIN Flag Count | 0.4971 | 0.5029 | lower in target | no |
| ECE Flag Count | 0.4999 | 0.5001 | lower in target | no |
| RST Flag Count | 0.4999 | 0.5001 | lower in target | no |
| Bwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd PSH Flags | 0.5000 | 0.5000 | higher in target | yes |
| Bwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| CWE Flag Count | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| distinct_dst_ports_1m | 0.5000 | 0.5000 | higher in target | yes |
| flow_inter_arrival_variance | 0.5000 | 0.5000 | higher in target | yes |
| mean_bytes_per_flow | 0.5000 | 0.5000 | higher in target | yes |
| syn_to_ack_ratio | 0.5000 | 0.5000 | higher in target | yes |
| win_flow_rate_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_syn_only_ratio_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ips_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ports_60s | 0.5000 | 0.5000 | higher in target | yes |

### BruteForce

Rows: 63438 total; 1379 target and 62059 BENIGN. Target test sessions: Tuesday-WorkingHours.pcap_ISCX.csv.

| Feature | Raw AUC (target=1) | Separation AUC | Direction | Constant in test? |
|---|---:|---:|---|---|
| Init_Win_bytes_forward | 0.8187 | 0.8187 | higher in target | no |
| Fwd Header Length | 0.8169 | 0.8169 | higher in target | no |
| Fwd Header Length.1 | 0.8169 | 0.8169 | higher in target | no |
| Fwd IAT Total | 0.7867 | 0.7867 | higher in target | no |
| Subflow Bwd Packets | 0.7816 | 0.7816 | higher in target | no |
| Total Backward Packets | 0.7816 | 0.7816 | higher in target | no |
| fwd_bwd_byte_ratio | 0.7802 | 0.7802 | higher in target | no |
| Bwd Header Length | 0.7771 | 0.7771 | higher in target | no |
| Subflow Fwd Packets | 0.7740 | 0.7740 | higher in target | no |
| Total Fwd Packets | 0.7740 | 0.7740 | higher in target | no |
| act_data_pkt_fwd | 0.7722 | 0.7722 | higher in target | no |
| iat_cv | 0.7653 | 0.7653 | higher in target | no |
| Bwd IAT Std | 0.7624 | 0.7624 | higher in target | no |
| PSH Flag Count | 0.7616 | 0.7616 | higher in target | no |
| Fwd Packet Length Std | 0.7517 | 0.7517 | higher in target | no |
| min_seg_size_forward | 0.7516 | 0.7516 | higher in target | no |
| Fwd IAT Mean | 0.7497 | 0.7497 | higher in target | no |
| Fwd IAT Max | 0.7454 | 0.7454 | higher in target | no |
| Fwd IAT Min | 0.7409 | 0.7409 | higher in target | no |
| Bwd Packet Length Min | 0.2624 | 0.7376 | lower in target | no |
| Fwd Packet Length Min | 0.2654 | 0.7346 | lower in target | no |
| Min Packet Length | 0.2662 | 0.7338 | lower in target | no |
| Flow Duration | 0.7224 | 0.7224 | higher in target | no |
| Bwd IAT Total | 0.7223 | 0.7223 | higher in target | no |
| Fwd IAT Std | 0.7129 | 0.7129 | higher in target | no |
| Bwd IAT Mean | 0.7095 | 0.7095 | higher in target | no |
| Bwd IAT Max | 0.7087 | 0.7087 | higher in target | no |
| Init_Win_bytes_backward | 0.7042 | 0.7042 | higher in target | no |
| Flow IAT Std | 0.6949 | 0.6949 | higher in target | no |
| Fwd Packets/s | 0.3121 | 0.6879 | lower in target | no |
| Bwd Packet Length Std | 0.6874 | 0.6874 | higher in target | no |
| Flow Packets/s | 0.3248 | 0.6752 | lower in target | no |
| Subflow Fwd Bytes | 0.6722 | 0.6722 | higher in target | no |
| Total Length of Fwd Packets | 0.6722 | 0.6722 | higher in target | no |
| Flow IAT Mean | 0.6712 | 0.6712 | higher in target | no |
| Avg Bwd Segment Size | 0.3339 | 0.6661 | lower in target | no |
| Bwd Packet Length Mean | 0.3339 | 0.6661 | lower in target | no |
| Flow IAT Max | 0.6586 | 0.6586 | higher in target | no |
| Average Packet Size | 0.3610 | 0.6390 | lower in target | no |
| is_well_known_port | 0.5984 | 0.5984 | higher in target | no |
| Packet Length Mean | 0.4061 | 0.5939 | lower in target | no |
| Flow Bytes/s | 0.4110 | 0.5890 | lower in target | no |
| Flow IAT Min | 0.4172 | 0.5828 | lower in target | no |
| Bwd Packets/s | 0.4206 | 0.5794 | lower in target | no |
| Idle Max | 0.4217 | 0.5783 | lower in target | no |
| Idle Mean | 0.4217 | 0.5783 | lower in target | no |
| Idle Min | 0.4217 | 0.5783 | lower in target | no |
| Active Max | 0.4219 | 0.5781 | lower in target | no |
| Active Mean | 0.4219 | 0.5781 | lower in target | no |
| Active Min | 0.4219 | 0.5781 | lower in target | no |
| Fwd PSH Flags | 0.5721 | 0.5721 | higher in target | no |
| SYN Flag Count | 0.5721 | 0.5721 | higher in target | no |
| is_ephemeral_port | 0.4306 | 0.5694 | lower in target | no |
| Subflow Bwd Bytes | 0.5692 | 0.5692 | higher in target | no |
| Total Length of Bwd Packets | 0.5692 | 0.5692 | higher in target | no |
| Down/Up Ratio | 0.5594 | 0.5594 | higher in target | no |
| Max Packet Length | 0.4449 | 0.5551 | lower in target | no |
| Bwd Packet Length Max | 0.4499 | 0.5501 | lower in target | no |
| Idle Std | 0.4530 | 0.5470 | lower in target | no |
| Active Std | 0.4532 | 0.5468 | lower in target | no |
| URG Flag Count | 0.4588 | 0.5412 | lower in target | no |
| Packet Length Std | 0.4701 | 0.5299 | lower in target | no |
| Packet Length Variance | 0.4701 | 0.5299 | lower in target | no |
| is_registered_port | 0.4710 | 0.5290 | lower in target | no |
| Avg Fwd Segment Size | 0.4754 | 0.5246 | lower in target | no |
| Fwd Packet Length Mean | 0.4754 | 0.5246 | lower in target | no |
| ACK Flag Count | 0.4755 | 0.5245 | lower in target | no |
| Fwd Packet Length Max | 0.4769 | 0.5231 | lower in target | no |
| Bwd IAT Min | 0.5179 | 0.5179 | higher in target | no |
| FIN Flag Count | 0.4942 | 0.5058 | lower in target | no |
| ECE Flag Count | 0.4998 | 0.5002 | lower in target | no |
| RST Flag Count | 0.4998 | 0.5002 | lower in target | no |
| Bwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd PSH Flags | 0.5000 | 0.5000 | higher in target | yes |
| Bwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| CWE Flag Count | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| distinct_dst_ports_1m | 0.5000 | 0.5000 | higher in target | yes |
| flow_inter_arrival_variance | 0.5000 | 0.5000 | higher in target | yes |
| mean_bytes_per_flow | 0.5000 | 0.5000 | higher in target | yes |
| syn_to_ack_ratio | 0.5000 | 0.5000 | higher in target | yes |
| win_flow_rate_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_syn_only_ratio_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ips_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ports_60s | 0.5000 | 0.5000 | higher in target | yes |

### PortScan

Rows: 31083 total; 13730 target and 17353 BENIGN. Target test sessions: Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.

| Feature | Raw AUC (target=1) | Separation AUC | Direction | Constant in test? |
|---|---:|---:|---|---|
| Bwd Packets/s | 0.9393 | 0.9393 | higher in target | no |
| Avg Fwd Segment Size | 0.0712 | 0.9288 | lower in target | no |
| Fwd Packet Length Mean | 0.0712 | 0.9288 | lower in target | no |
| Subflow Fwd Bytes | 0.0713 | 0.9287 | lower in target | no |
| Total Length of Fwd Packets | 0.0713 | 0.9287 | lower in target | no |
| Fwd Packet Length Max | 0.0714 | 0.9286 | lower in target | no |
| Packet Length Mean | 0.1022 | 0.8978 | lower in target | no |
| Flow Duration | 0.1031 | 0.8969 | lower in target | no |
| Flow IAT Max | 0.1061 | 0.8939 | lower in target | no |
| Average Packet Size | 0.1086 | 0.8914 | lower in target | no |
| Flow Packets/s | 0.8867 | 0.8867 | higher in target | no |
| Fwd Packets/s | 0.8829 | 0.8829 | higher in target | no |
| Subflow Fwd Packets | 0.1308 | 0.8692 | lower in target | no |
| Total Fwd Packets | 0.1308 | 0.8692 | lower in target | no |
| PSH Flag Count | 0.8679 | 0.8679 | higher in target | no |
| Fwd IAT Total | 0.1341 | 0.8659 | lower in target | no |
| Fwd IAT Max | 0.1343 | 0.8657 | lower in target | no |
| Fwd IAT Mean | 0.1344 | 0.8656 | lower in target | no |
| Fwd IAT Min | 0.1381 | 0.8619 | lower in target | no |
| Flow IAT Mean | 0.1393 | 0.8607 | lower in target | no |
| act_data_pkt_fwd | 0.1549 | 0.8451 | lower in target | no |
| is_registered_port | 0.8416 | 0.8416 | higher in target | no |
| Max Packet Length | 0.1613 | 0.8387 | lower in target | no |
| iat_cv | 0.1712 | 0.8288 | lower in target | no |
| Flow IAT Std | 0.1723 | 0.8277 | lower in target | no |
| is_well_known_port | 0.1842 | 0.8158 | lower in target | no |
| Bwd Header Length | 0.1970 | 0.8030 | lower in target | no |
| Init_Win_bytes_forward | 0.7994 | 0.7994 | higher in target | no |
| Bwd IAT Total | 0.2096 | 0.7904 | lower in target | no |
| Bwd IAT Max | 0.2098 | 0.7902 | lower in target | no |
| Bwd IAT Mean | 0.2099 | 0.7901 | lower in target | no |
| Bwd IAT Min | 0.2117 | 0.7883 | lower in target | no |
| fwd_bwd_byte_ratio | 0.2118 | 0.7882 | lower in target | no |
| min_seg_size_forward | 0.7742 | 0.7742 | higher in target | no |
| Packet Length Std | 0.2275 | 0.7725 | lower in target | no |
| Packet Length Variance | 0.2275 | 0.7725 | lower in target | no |
| Fwd Header Length | 0.2374 | 0.7626 | lower in target | no |
| Fwd Header Length.1 | 0.2374 | 0.7626 | lower in target | no |
| Subflow Bwd Bytes | 0.2391 | 0.7609 | lower in target | no |
| Total Length of Bwd Packets | 0.2391 | 0.7609 | lower in target | no |
| Flow Bytes/s | 0.7528 | 0.7528 | higher in target | no |
| Bwd Packet Length Max | 0.2473 | 0.7527 | lower in target | no |
| Avg Bwd Segment Size | 0.2505 | 0.7495 | lower in target | no |
| Bwd Packet Length Mean | 0.2505 | 0.7495 | lower in target | no |
| Subflow Bwd Packets | 0.2670 | 0.7330 | lower in target | no |
| Total Backward Packets | 0.2670 | 0.7330 | lower in target | no |
| Fwd Packet Length Min | 0.2826 | 0.7174 | lower in target | no |
| Min Packet Length | 0.2888 | 0.7112 | lower in target | no |
| Fwd IAT Std | 0.3152 | 0.6848 | lower in target | no |
| Fwd Packet Length Std | 0.3275 | 0.6725 | lower in target | no |
| Down/Up Ratio | 0.6617 | 0.6617 | higher in target | no |
| Flow IAT Min | 0.6472 | 0.6472 | higher in target | no |
| ACK Flag Count | 0.3600 | 0.6400 | lower in target | no |
| Bwd IAT Std | 0.3671 | 0.6329 | lower in target | no |
| Bwd Packet Length Std | 0.3686 | 0.6314 | lower in target | no |
| Active Max | 0.4092 | 0.5908 | lower in target | no |
| Active Mean | 0.4092 | 0.5908 | lower in target | no |
| Active Min | 0.4092 | 0.5908 | lower in target | no |
| Idle Max | 0.4095 | 0.5905 | lower in target | no |
| Idle Mean | 0.4095 | 0.5905 | lower in target | no |
| Idle Min | 0.4096 | 0.5904 | lower in target | no |
| Init_Win_bytes_backward | 0.5869 | 0.5869 | higher in target | no |
| Active Std | 0.4407 | 0.5593 | lower in target | no |
| Idle Std | 0.4407 | 0.5593 | lower in target | no |
| URG Flag Count | 0.4476 | 0.5524 | lower in target | no |
| Fwd PSH Flags | 0.4738 | 0.5262 | lower in target | no |
| SYN Flag Count | 0.4738 | 0.5262 | lower in target | no |
| is_ephemeral_port | 0.4741 | 0.5259 | lower in target | no |
| Bwd Packet Length Min | 0.4837 | 0.5163 | lower in target | no |
| FIN Flag Count | 0.4950 | 0.5050 | lower in target | no |
| ECE Flag Count | 0.4999 | 0.5001 | lower in target | no |
| RST Flag Count | 0.4999 | 0.5001 | lower in target | no |
| Bwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Bwd PSH Flags | 0.5000 | 0.5000 | higher in target | yes |
| Bwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| CWE Flag Count | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bulk Rate | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Bytes/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd Avg Packets/Bulk | 0.5000 | 0.5000 | higher in target | yes |
| Fwd URG Flags | 0.5000 | 0.5000 | higher in target | yes |
| distinct_dst_ports_1m | 0.5000 | 0.5000 | higher in target | yes |
| flow_inter_arrival_variance | 0.5000 | 0.5000 | higher in target | yes |
| mean_bytes_per_flow | 0.5000 | 0.5000 | higher in target | yes |
| syn_to_ack_ratio | 0.5000 | 0.5000 | higher in target | yes |
| win_flow_rate_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_syn_only_ratio_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ips_60s | 0.5000 | 0.5000 | higher in target | yes |
| win_unique_dst_ports_60s | 0.5000 | 0.5000 | higher in target | yes |

## Constant and near-constant training features

A feature is constant when all actual model-training values in a fold are identical. Near-constant means one value accounts for at least 99% of that fold’s capped training rows. Counts below are out of 25 family/seed folds; this is a fold-level diagnostic, not a feature-selection step.

| Feature | Constant folds | Near-constant folds (not constant) | Maximum dominant-value share |
|---|---:|---:|---:|
| Bwd Avg Bulk Rate | 25 | 0 | 1.0000 |
| Bwd Avg Bytes/Bulk | 25 | 0 | 1.0000 |
| Bwd Avg Packets/Bulk | 25 | 0 | 1.0000 |
| Bwd PSH Flags | 25 | 0 | 1.0000 |
| Bwd URG Flags | 25 | 0 | 1.0000 |
| CWE Flag Count | 5 | 20 | 1.0000 |
| ECE Flag Count | 0 | 25 | 0.9999 |
| FIN Flag Count | 0 | 9 | 0.9939 |
| Fwd Avg Bulk Rate | 25 | 0 | 1.0000 |
| Fwd Avg Bytes/Bulk | 25 | 0 | 1.0000 |
| Fwd Avg Packets/Bulk | 25 | 0 | 1.0000 |
| Fwd URG Flags | 5 | 20 | 1.0000 |
| RST Flag Count | 0 | 25 | 0.9999 |
| distinct_dst_ports_1m | 25 | 0 | 1.0000 |
| flow_inter_arrival_variance | 25 | 0 | 1.0000 |
| mean_bytes_per_flow | 25 | 0 | 1.0000 |
| syn_to_ack_ratio | 25 | 0 | 1.0000 |
| win_flow_rate_60s | 25 | 0 | 1.0000 |
| win_syn_only_ratio_60s | 25 | 0 | 1.0000 |
| win_unique_dst_ips_60s | 25 | 0 | 1.0000 |
| win_unique_dst_ports_60s | 25 | 0 | 1.0000 |

Host-window fields appear in the feature interface but are all-zero for the CICIDS2017 baseline because the source files lack the required timestamp/source-host fields; they therefore cannot separate these classes in this evaluation.

## Exact and near-duplicate diagnostics

Exact duplicates are hashed over the fold’s sanitized numeric model-input columns, excluding labels. Within-split `extra duplicate rows` counts rows beyond the first occurrence. Cross-split counts are full-data exact hash intersections. Near duplicates are a deterministic sample of up to 250 rows per split, standardized using that fold’s train values (after the same log1p policy); a non-identical pair at Euclidean distance ≤0.05 is called near. Near counts are sample-only and do not estimate full-population rates.

| Held-out family | Seed | Exact extras train / val / test | Exact matched rows train-val / train-test / val-test | Exact shared unique vectors train-val / train-test / val-test | Sampled near pairs within train / val / test | Sampled near pairs train-val / train-test / val-test |
|---|---:|---|---|---|---|---|
| DosDDoS | 42 | 6951 / 441 / 2157 | 529 / 1083 / 719 | 344 / 656 / 439 | 8 / 4 / 5 | 6 / 0 / 7 |
| DosDDoS | 101 | 2445 / 13115 / 2157 | 464 / 1112 / 561 | 317 / 680 / 379 | 7 / 182 / 2 | 3 / 8 / 2 |
| DosDDoS | 202 | 6922 / 441 / 2157 | 521 / 1024 / 719 | 340 / 619 / 439 | 24 / 5 / 4 | 6 / 5 / 9 |
| DosDDoS | 303 | 8881 / 2460 / 2157 | 455 / 1305 / 612 | 289 / 739 / 339 | 29 / 4 / 4 | 4 / 6 / 1 |
| DosDDoS | 404 | 7001 / 441 / 2157 | 529 / 1046 / 719 | 343 / 631 / 439 | 10 / 1 / 5 | 10 / 9 / 9 |
| PortScan | 42 | 1729 / 87 / 13115 | 225 / 451 / 157 | 162 / 308 / 110 | 2 / 8 / 249 | 6 / 1 / 4 |
| PortScan | 101 | 1733 / 87 / 13115 | 217 / 442 / 157 | 163 / 302 / 110 | 0 / 3 / 337 | 1 / 2 / 1 |
| PortScan | 202 | 971 / 4018 / 13115 | 614 / 394 / 469 | 394 / 263 / 311 | 3 / 11 / 119 | 2 / 5 / 3 |
| PortScan | 303 | 1960 / 1883 / 13115 | 980 / 453 / 518 | 583 / 303 / 344 | 3 / 1 / 203 | 5 / 0 / 3 |
| PortScan | 404 | 1533 / 411 / 13115 | 457 / 415 / 288 | 313 / 278 / 201 | 1 / 6 / 329 | 1 / 0 / 9 |
| BruteForce | 42 | 5118 / 87 / 2460 | 237 / 446 / 49 | 177 / 262 / 43 | 6 / 8 / 2 | 4 / 3 / 0 |
| BruteForce | 101 | 5087 / 87 / 2460 | 240 / 432 / 49 | 184 / 258 / 43 | 15 / 24 / 10 | 3 / 6 / 0 |
| BruteForce | 202 | 4848 / 441 / 2460 | 554 / 388 / 258 | 346 / 230 / 179 | 2 / 6 / 1 | 4 / 2 / 4 |
| BruteForce | 303 | 6704 / 1883 / 2460 | 1085 / 389 / 589 | 623 / 246 / 325 | 11 / 1 / 4 | 2 / 5 / 2 |
| BruteForce | 404 | 4261 / 4018 / 2460 | 727 / 399 / 328 | 458 / 254 / 227 | 5 / 22 / 2 | 11 / 2 / 0 |
| WebAttack | 42 | 4382 / 87 / 411 | 209 / 476 / 162 | 158 / 327 / 121 | 7 / 34 / 6 | 1 / 3 / 3 |
| WebAttack | 101 | 4428 / 87 / 411 | 217 / 486 / 162 | 162 / 330 / 121 | 4 / 23 / 14 | 3 / 7 / 2 |
| WebAttack | 202 | 4044 / 441 / 411 | 503 / 433 / 340 | 313 / 295 / 234 | 2 / 3 / 3 | 3 / 4 / 7 |
| WebAttack | 303 | 5550 / 1883 / 411 | 908 / 445 / 596 | 526 / 297 / 403 | 13 / 1 / 7 | 3 / 12 / 4 |
| WebAttack | 404 | 3790 / 4018 / 411 | 662 / 430 / 424 | 422 / 286 / 291 | 17 / 22 / 11 | 8 / 4 / 10 |
| Bot | 42 | 4425 / 87 / 441 | 202 / 498 / 159 | 152 / 318 / 119 | 15 / 8 / 3 | 3 / 3 / 6 |
| Bot | 101 | 4456 / 87 / 441 | 221 / 545 / 159 | 168 / 336 / 119 | 5 / 3 / 9 | 1 / 4 / 0 |
| Bot | 202 | 3765 / 4018 / 441 | 661 / 468 / 474 | 432 / 300 / 297 | 8 / 12 / 3 | 7 / 5 / 5 |
| Bot | 303 | 5573 / 1883 / 441 | 894 / 480 / 674 | 554 / 319 / 400 | 12 / 1 / 6 | 2 / 8 / 4 |
| Bot | 404 | 4133 / 411 / 441 | 440 / 505 / 340 | 293 / 321 / 234 | 6 / 10 / 6 | 5 / 9 / 13 |

The baseline loader also performs global exact-flow deduplication before session splitting. On the sampled development source rows, it removed 42,760 repeated feature/label rows and removed 238 feature-identical conflicting-label rows. After that deduplication, the model-input hash check found 37 distinct feature vectors spanning multiple labels across 1,473 rows. The upstream conflict count is a label-noise indicator, not proof which label is wrong; source duplicates were dropped before model fitting.

## Data, feature, or model limitation hypotheses

- **Bot:** likely a mixture of data coverage and open-set model/decision limitation. The held-out one-session sample has only 305 rows, yet several individual features separate it from BENIGN (best separation AUC 0.911). This shows univariate signal in this capture, but does not establish cross-session signal; threshold/model use versus capture shift remains unresolved. No reliable known-class confusion destination is estimable: Bot has no supported known-only, session-disjoint test rows in these folds.
- **WebAttack:** likely data coverage plus a model/decision limitation in the observed capture. Despite only 320 target rows from one session, several features have high univariate separation (best 0.933). This suggests potentially useful flow-level signal, but a single capture cannot establish generalization. No reliable known-class confusion destination is estimable for the same split-support reason.
- **BruteForce:** evidence suggests usable univariate flow signal (best separation AUC 0.819) while unknown-review F1 remains low (0.132); this makes model/decision use a plausible limitation, alongside the dominant data limitation of one held-out source session. The current splits provide no supported known-only test rows for a reliable confusion-destination estimate.
- **PortScan:** strong univariate separation exists in the held-out capture (best separation AUC 0.939), but unknown-review F1 is only 0.188; model/decision use is a plausible limitation. Data coverage is still only one source session. Host-window features are constant zero because the CICIDS inputs lack the timestamp/source-host context required to populate them, so that temporal/context signal is also absent. No reliable known-class confusion destination is estimable from these session-disjoint folds.

These are hypotheses for selecting Step B diagnostics, not conclusions that any model change improves performance. No experiment was run, no model or split was changed, no test metric was used for tuning, and no labels or data were fabricated.
