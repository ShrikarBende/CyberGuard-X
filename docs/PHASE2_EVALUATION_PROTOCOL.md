# Phase 2 B0 — Evaluation protocol proposal

Status: proposal only. No model experiment, split change, dataset download, or metric selection was performed for this protocol review. Existing measurements below come from the frozen Phase 1 development sample and the already-generated [error analysis](ERROR_ANALYSIS.md).

## 1. Current data support and overlap

The Phase 1 development manifest has seven capture CSVs spanning Tuesday through Friday. Here, an independent session means a distinct source capture file; distinct files on the same day are not independent days. The target-family support in this frozen development scope is:

| Target family | Capture files/sessions containing target | Capture days | Target flows in held-out file, after Phase 1 sampling/deduplication | Total flows in that held-out file after sampling/deduplication |
|---|---:|---:|---:|---:|
| Bot | 1: `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 1 (Friday) | 305 | 25,905 |
| WebAttack | 1: `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 1 (Thursday) | 320 | 23,423 |
| BruteForce | 1: `Tuesday-WorkingHours.pcap_ISCX.csv` | 1 (Tuesday) | 1,379 | 63,438 |
| PortScan | 1: `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 1 (Friday) | 13,730 | 31,083 |

These are the four target-family held-out test files in the current Phase 1 development sample. The reserved Monday holdout file was not read for this audit; no claim is made here about its per-class composition. All seven checked-in development CSVs have the same 79-column header (78 numeric feature columns plus `Label`) and omit per-flow `Timestamp`, `Flow ID`, source/destination IP, and protocol columns. The frozen evaluator rejects a newly appearing `Timestamp` rather than silently changing its split policy. The original CICIDS2017 documentation describes time-stamped labeled flows and identifiers, but those fields are absent from the current local machine-learning CSV export. Thus, time-blocked evaluation might be possible after obtaining and verifying the richer official flows or re-extracting PCAPs; it is infeasible on the current local CSVs. Row order alone is not evidence of chronology.

## 1.1 CSE-CIC-IDS2018 documentation-only inventory

The official AWS Open Data entry describes the bucket as accessible without an AWS account (`aws s3 ls --no-sign-request`); no bucket listing or data download was performed. The official CIC/UNB documentation provides attack schedules and scenario descriptions, but not per-label/per-day flow counts. Therefore all CSE flow counts below are **UNVERIFIED**. Dates are documented scenario dates, not a claim that each downloadable day file contains a particular labeled-flow count.

| CyberGuardX family | Documented CSE-CIC-IDS2018 dates | Official attack/scenario labels or names in documentation | Approximate flow counts | Mapping judgment |
|---|---|---|---|---|
| Bot | 2018-03-02 | `Bot` (Ares botnet scenario; the documentation also describes Zeus) | **UNVERIFIED**; no official class/day count located | Defensible umbrella mapping to `Bot`, subject to confirming actual CSV labels and flows. Keep Botnet/Zeus/Ares provenance. |
| BruteForce | 2018-02-14 | `FTP-BruteForce`, `SSH-Bruteforce` | **UNVERIFIED** | Defensible mapping of both credential-guessing labels to `BruteForce`; do not merge the source labels until reporting them separately too. |
| WebAttack | 2018-02-22, 2018-02-23 | `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`; official scenario: web attacks | **UNVERIFIED** | Defensible umbrella mapping to `WebAttack`, with original subtype retained. Confirm actual CSV labels; not all attack names are identical to CICIDS2017 labels. |
| PortScan | Dates for the `DDoS+PortScan` scenario are **UNVERIFIED**; Nmap/port-scan activity is described within `Infiltration` on 2018-02-28 and 2018-03-01 | Scenario name `DDoS+PortScan`; `Infiltration` label/scenario includes Nmap port scanning | **UNVERIFIED** | No defensible per-flow `PortScan` mapping established. A mixed DDoS+PortScan scenario or `Infiltration` label is not equivalent to a clean PortScan class. A separate `PortScan` flow label is **UNVERIFIED**. |
| DoS/DDoS | 2018-02-15, 2018-02-16 (DoS); 2018-02-20, 2018-02-21 (DDoS) | `DoS-GoldenEye`, `DoS-Slowloris`, `DoS-SlowHTTPTest`, `DoS-Hulk`, `DDoS attacks-LOIC-HTTP`, `DDoS-LOIC-UDP`, `DDOS-LOIC-UDP`, `DDOS-HOIC` | **UNVERIFIED** | Defensible `DosDDoS` umbrella for the explicitly named DoS and DDoS events, keeping source subtype and event date. The mixed `DDoS+PortScan` scenario needs separate handling. |

The documented dates show ten CSE attack days: February 14–16, February 20–23, February 28, March 1, and March 2, 2018. The official page says the data are organized by day and lists flow output identifiers, but the documentation does not establish a timestamp column in the released per-flow CSV or prove that `FlowID` sorts chronologically. Both are **UNVERIFIED** until the actual schema is inspected after acquisition.

## 1.2 Feature schema compatibility

The checked-in CICIDS2017 headers are the 78 numeric flow columns plus `Label`; the project’s fold preprocessing adds engineered columns and removes raw destination port and identifier-like fields from the model matrix. The CICIDS2017 official page says CICFlowMeter but does not pin a version. CSE-CIC-IDS2018 documents 80 features from CICFlowMeter-V3 and per-flow identifiers (`FlowID`, `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `Protocol`). CSE feature names are abbreviated in the official feature table, unlike the local 2017 CSV names. Exact column intersection and value equivalence cannot be certified without reading the acquired CSE schema and documenting its exporter/version.

| CyberGuardX feature group | Candidate mapping to CSE documentation | Status and cautions |
|---|---|---|
| Flow duration; forward/backward packet counts and byte totals; directional packet-length min/max/mean/std; flow and directional IAT summaries; packet/byte rates; header lengths; TCP flags; packet-length summaries; active/idle summaries; subflow counts/bytes; initial TCP windows; down/up ratio; forward/backward segment-size summaries | Corresponding CICFlowMeter-V3 statistical features are documented in CSE under abbreviated names | **Candidate common definitions, not certified equal as released.** The 2017 exporter version is unspecified; names, units, timeout behavior, direction handling, zero/infinity handling, and formula details must be compared or both sources re-extracted with one pinned version. `Flow IAT` descriptions and rate definitions require particular verification. |
| `iat_cv`, `fwd_bwd_byte_ratio` | Recompute from the matching IAT standard deviation/mean and forward/backward byte totals | Computable only after the underlying columns are confirmed equivalent; not safe to transfer by name alone. |
| `is_well_known_port`, `is_registered_port`, `is_ephemeral_port` | Derive from `Destination Port` / CSE `DestinationPort` metadata | Candidate consistent derivations if destination-port direction and integer parsing match; keep raw ports excluded from model inputs. |
| `distinct_dst_ports_1m`, `syn_to_ack_ratio`, `flow_inter_arrival_variance`, `mean_bytes_per_flow`, `win_unique_dst_ports_60s`, `win_unique_dst_ips_60s`, `win_syn_only_ratio_60s`, `win_flow_rate_60s` | Require source identity, destination/port and, for a true time window, per-flow timestamps plus causal ordering | Not computable from the current 2017 CSVs. CSE documents source/destination IP and ports but per-flow timestamp availability is **UNVERIFIED**; do not treat file order or an unverified FlowID as time. These context fields currently become zeros in this baseline and cannot provide cross-dataset evidence. |
| `Flow ID`, IP addresses, source port, timestamp, protocol | CSE documents these identifiers except a per-flow timestamp; current local 2017 ML CSV omits them | Identifier metadata is for grouping/audit only, not model features. 2017 official richer flow exports may have timestamp and IDs, but that is a different local input than the frozen evaluation sample. |

For exact cross-dataset evaluation, the safe plan is to freeze a common feature specification and either validate every mapped feature against documented formulas or re-extract both PCAP datasets with the same pinned CICFlowMeter build and timeout configuration. Until then, no feature is certified as exactly equivalent solely from documentation. The current local feature matrix is not directly compatible with the CSE schema.

The split-level duplicate counts below are based on Phase 1 model-input feature hashes after its global source-row deduplication; they are not counts of byte-identical raw CSV records. “Exact train/test matches” counts test rows whose sanitized model-input vector also occurs in the capped training split. The near-duplicate figure is only the deterministic pair count from samples of at most 250 rows per split, standardized using training statistics; it is not a population estimate.

| Held-out family | Seed | Held-out test rows | Exact test rows also in train | Sampled near train/test pairs |
|---|---:|---:|---:|---:|
| Bot | 42 | 25,905 | 498 | 3 |
| Bot | 101 | 25,905 | 545 | 4 |
| Bot | 202 | 25,905 | 468 | 5 |
| Bot | 303 | 25,905 | 480 | 8 |
| Bot | 404 | 25,905 | 505 | 9 |
| WebAttack | 42 | 23,423 | 476 | 3 |
| WebAttack | 101 | 23,423 | 486 | 7 |
| WebAttack | 202 | 23,423 | 433 | 4 |
| WebAttack | 303 | 23,423 | 445 | 12 |
| WebAttack | 404 | 23,423 | 430 | 4 |
| BruteForce | 42 | 63,438 | 446 | 3 |
| BruteForce | 101 | 63,438 | 432 | 6 |
| BruteForce | 202 | 63,438 | 388 | 2 |
| BruteForce | 303 | 63,438 | 389 | 5 |
| BruteForce | 404 | 63,438 | 399 | 2 |
| PortScan | 42 | 31,083 | 451 | 1 |
| PortScan | 101 | 31,083 | 442 | 2 |
| PortScan | 202 | 31,083 | 394 | 5 |
| PortScan | 303 | 31,083 | 453 | 0 |
| PortScan | 404 | 31,083 | 415 | 0 |

Exact train/test matches range 388–545 rows per fold for these targets. This is about 0.6%–2.1% of each held-out file, depending on family and fold. The sampled near-pair counts are small, but sample-only and should not be interpreted as evidence that the full data have few near duplicates. The error-analysis report has the corresponding exact and sampled near-duplicate diagnostics for all 25 family/seed folds.

## 2. Candidate protocols

### A. Time-blocked splits within each capture, with a gap

- **Measures:** within-capture future-block generalization and sensitivity to temporal drift, if reliable flow timestamps and stable flow identity exist.
- **Cannot measure:** generalization to a different capture, day, site, or collection setup.
- **Leakage risks:** adjacent or repeated flows can cross the boundary; a gap must be based on actual flow duration/aggregation windows and duplicate analysis, not an arbitrary row count. Sorting by file row order is invalid without provenance that the order is chronological.
- **Effort:** high for this repository. The current source CSVs have no `Timestamp`, `Flow ID`, or host identity. This protocol is infeasible on the current checked-in feature tables. It would require a verified richer source export or re-extraction from packet captures, plus a documented gap rule and data lineage.

### B. Leave-one-capture-out where multiple captures exist

- **Measures:** generalization to a distinct capture file within one dataset; grouping multiple files from the same day/site may reduce within-day dependence.
- **Cannot measure:** broad cross-dataset or deployment generalization. It also cannot produce repeated held-out target-family sessions if that family exists in only one capture.
- **Leakage risks:** files from the same day, host, attack campaign, or duplicated flow set may not be independent. Exact/near duplicates and capture provenance must be checked before treating files as separate units.
- **Effort:** low to moderate for the current splitter, but it does not solve the target support problem: each of the four target families has only one capture in the frozen Phase 1 development files. Its family-specific test count remains n=1.

### C. Cross-dataset evaluation using CSE-CIC-IDS2018 or UNSW-NB15

- **Measures:** external transfer to a different capture/testbed and data-generation process. The official CSE-CIC-IDS2018 description schedules the matching Bot, brute-force, web, and DoS/DDoS scenarios across documented dates; it organizes the data by day. The AWS Open Data entry says access requires no AWS account. [Official CSE-CIC-IDS2018 description](https://www.unb.ca/cic/datasets/ids-2018.html), [AWS Open Data entry](https://registry.opendata.aws/cse-cic-ids2018/)
- **Cannot measure:** same-distribution CICIDS2017 performance. CSE labels/scenarios are not identical (especially PortScan, which is mixed with DDoS or Infiltration), and two datasets do not establish broad domain generalization. The documented Bot and brute-force events are each on one day. Actual per-day flow labels and counts remain unverified.
- **Leakage risks:** train/test source overlap, cross-day duplicate flows, feature/label mapping errors, feature schema mismatch, and using external test results to select thresholds or model settings. Keep all external test captures out of fitting and selection; perform a source/file/day provenance and duplicate audit first.
- **Effort:** high. Inventory and verify source files, harmonize only an explicitly fixed common feature set, pre-register label mappings, handle missing fields without fabricating values, establish capture-day groups, and freeze a baseline before testing candidate changes. AUC from the official scenario descriptions is not a substitute for verifying the actual flow labels and capture counts.

UNSW-NB15 has nine official attack categories including Reconnaissance, DoS, and Exploits, but not direct labels equivalent to Bot, WebAttack, BruteForce, and PortScan. It is therefore not a direct per-family primary evaluation without a separately justified taxonomy mapping; such mapping could change the task definition. [Official UNSW-NB15 description](https://research.unsw.edu.au/projects/unsw-nb15-dataset)

### D. Binary attack-versus-benign leave-one-capture-day-out

- **Protocol:** label `BENIGN` as negative and every documented attack label as positive, preserving original labels in metadata. Group every capture file from the same dataset and calendar date into one held-out unit; never split a day across train, validation, and test. On 2017, the frozen development scope has four attack days (Tuesday–Friday); Monday is the untouched benign-only holdout and is excluded. Official CSE documentation lists ten attack dates. The planned combined inventory therefore yields **4 held-out day units on CICIDS2017 alone** and **14 units on CICIDS2017+CSE-CIC-IDS2018** (4+10), conditional on obtaining the CSE files and verifying their date/file inventory. These are capture-day units, not 14 independent datasets; there are only two dataset domains.
- **Measures:** generic attack-versus-benign discrimination across held-out capture days. It can test a binary detector but does not test open-set rejection or distinguish which attack family is present.
- **Cannot measure:** family classification, family-specific false-accept destinations, or generalization to entirely unseen dataset domains. Per-family recall on each held-out day is descriptive only; a day with no examples for a family contributes no family recall estimate.
- **Metrics/reporting:** report aggregate binary AUPRC and F1 (plus confusion counts) with a paired bootstrap over held-out capture-day units, and show results separately for 2017 and 2018 as well as pooled. Report each family’s recall per held-out day as `descriptive, n=<held-out day units with that family>`. The pooled interval must not be described as dataset-level uncertainty because it has only two datasets.
- **Leakage/effort:** verify day/file provenance, deduplicate across all days and datasets before splitting, preserve all non-BENIGN labels as attack, and audit source labels before binary mapping. Train and tune only on training/validation days. Moderate/high effort; data ingestion and common feature harmonization are prerequisites.

## 3. Recommendation and family decision table

**Primary candidate for family-specific changes:** leave-one-capture-day-out across the combined CICIDS2017 development scope and CSE-CIC-IDS2018, with a per-family gate of at least three verified held-out day units, validated labels, and a frozen common feature schema. The schedule suggests a possible gate for DoS/DDoS (2 2017 days + 4 CSE days) and WebAttack (1 + 2), but neither qualifies until actual CSE labels, counts, and feature equivalence are verified. Bot and BruteForce appear to have only two documented days each (one per dataset); PortScan has only one clean 2017 day and no defensible CSE per-flow mapping. These three cannot qualify on the documented inventory.

**Secondary:** frozen Phase 1 CICIDS2017 session-disjoint family evaluation. It remains useful for continuity and regression checks, but the single-session families are “indicative only.” It cannot alone accept/reject a change.

The binary attack-versus-benign protocol has 4 day units on 2017 alone and a proposed 14 on 2017+2018. It may be a primary protocol for a specifically binary attack-detection experiment after data/schema validation; it is not a primary acceptance protocol for family-specific multiclass or open-set changes. Its per-family recall is descriptive and cannot override the family decision table.

| Family | Candidate primary protocol | Secondary / indicative evidence | Current decision status |
|---|---|---|---|
| Bot | None currently qualifies. Combined day inventory is 2 (1 CICIDS2017 + 1 documented CSE day), below the three-unit gate. | Phase 1 CICIDS2017 n=1; binary per-day recall descriptive, candidate n=2. | **No reliable family-level accept/reject evaluation.** Experiments are exploratory only; may skip Step B and document data limitation. |
| BruteForce | None currently qualifies. Combined day inventory is 2 (1+1), below the gate. | Phase 1 n=1; binary per-day recall descriptive, candidate n=2. | **No reliable family-level accept/reject evaluation.** Experiments are exploratory only; may skip Step B and document data limitation. |
| WebAttack | Conditional combined capture-day family protocol: 3 scheduled days (1 CICIDS2017 + 2 CSE), only if actual labels/flows and common schema pass verification. | Phase 1 n=1; binary per-day recall descriptive, candidate n=3. | **Not qualified yet.** If CSE data verification fails or a day lacks labeled WebAttack flows, no reliable family-level accept/reject evaluation; experiments then exploratory only or skipped. |
| PortScan | None currently qualifies. Only one clean CICIDS2017 PortScan day; CSE documentation describes scan activity in mixed scenarios, not a verified separate flow label. | Phase 1 n=1; binary per-day recall descriptive; CSE port-scan attribution unverified. | **No reliable family-level accept/reject evaluation.** Experiments are exploratory only; may skip Step B and document data limitation. |
| DoS/DDoS | Conditional combined capture-day family protocol: 6 scheduled days (2 CICIDS2017 + 4 CSE), only if actual labels/flows and common schema pass verification. | Phase 1 family holdout includes 2 source sessions; binary per-day recall descriptive, candidate n=6. | **Not qualified yet.** Potentially sufficient unit count after audit; if data/schema/label checks fail, there is no reliable primary result. |

“Scheduled days” are counts from source documentation and the frozen 2017 development inventory, not verified CSE per-label flow counts. All family-specific decisions remain blocked until the CSE source audit passes.

## 4. Reporting and Phase 2 acceptance rules

1. Label every score and interval with its protocol and unit, for example: `CICIDS2017 source-capture holdout, n=1 session (indicative only)`, `CSE-CIC-IDS2018 capture-day holdout, n=4 days`, or `binary attack-vs-benign, leave-one-capture-day-out, 14 day units across 2 datasets`.
2. A result with n=1 held-out session is **indicative only**. It must not be the sole evidence to accept or reject a model change. Show the point estimate, interval, sample/flow count, and exact capture unit regardless.
3. Experiments may be accepted only on a qualified primary protocol. For a family with at least three verified held-out capture-day units and validated labels/schema, use a paired bootstrap over capture units (not just rows or random seeds) for the candidate-minus-frozen-baseline delta. Keep a change only when the preselected family outcome (macro-F1 or class AUPRC, fixed before the run) has a 95% paired interval whose lower bound is above zero. The binary protocol can accept/reject only a binary detector outcome, not a family-specific change.
4. On the single-session secondary evaluation, reject a candidate if its regression exceeds that protocol's predeclared noise bound. Estimate the bound with the same paired bootstrap procedure used for the frozen baseline and state explicitly that a row/seed interval from one capture does not estimate between-session uncertainty. The secondary result is a guard, not a substitute for the multi-session primary.
5. Preserve the existing OSCR non-regression rule: reject a change if OSCR drops beyond its predeclared bootstrap uncertainty interval. Report OSCR for both primary and secondary protocols where defined.
6. Validation data alone may select thresholds, hyperparameters, features, and model variants. Held-out primary and secondary results are run once for the chosen configuration; they are never used for selection. For families without a qualifying primary protocol, experiments are exploratory only, results must be labeled indicative, and defaults must not change based on them. Step B may be skipped entirely for such families; document the data limitation instead. Log every attempted experiment, including rejected experiments, with protocol, captures, configuration, metrics, intervals, and seed in `docs/EXPERIMENTS.md`.

This acceptance rule is a proposal for approval; no modeling experiment has been run under it.
