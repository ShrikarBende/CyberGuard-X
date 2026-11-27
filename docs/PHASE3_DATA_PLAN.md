# Phase 3 Data Plan

Status: **planning only (docs only)**. No dataset was downloaded, and no model, split, or feature change was made. Items not directly verified against acquired local files are marked **UNVERIFIED**.

---

## (a) CICIDS2017 files with timestamps and source IPs

### Obtainability and releases/versions
1. **Current local files (`backend/datasets/trafficlabelling/`):**
   - Although stored under `trafficlabelling/`, the 8 checked-in CSVs (`Monday-WorkingHours.pcap_ISCX.csv` through `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`) have the **79-column `MachineLearningCVE` schema** (78 numeric flow features + `Label`) and **omit** `Flow ID`, `Source IP`, `Destination IP`, `Source Port`, `Protocol`, and `Timestamp`.
   - `Destination Port` is present in the raw CSVs, and `cicids_pipeline.py` drops it from model inputs when `sanitize_session_features=True` (retaining only the port-bucket flags `is_well_known_port`, `is_registered_port`, `is_ephemeral_port`).

2. **Official CIC/UNB `TrafficLabelling` CSV archive (`GeneratedLabelledFlows.zip` / `TrafficLabelling`):**
   - Obtainable from the official UNB CICIDS2017 distribution (**UNVERIFIED** whether the current UNB download mirror still serves the exact same 85-column CSVs without registration/mirror changes).
   - Documented as containing 85 columns including `Flow ID`, `Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`, and `Timestamp` alongside the flow statistics and `Label`.

3. **Raw PCAPs (Monday–Friday) + re-extraction / corrected releases:**
   - Raw PCAPs are published by UNB CIC (**UNVERIFIED** current mirror availability/checksums).
   - Third-party corrected re-extractions exist in the literature—most notably **Engelen et al. (2021)** (*"Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study"*, DistriNet, KU Leuven), which provides corrected CICFlowMeter fixes and re-labeled CSVs (**UNVERIFIED** exact column names, schema parity, and current hosting availability).

### Known labeling and flow-construction issues
- **Official `MachineLearningCVE` / `TrafficLabelling` (original CICFlowMeter):**
  - **Labeling errors:** Engelen et al. (2021) reported that >20–25% of flows in the original CICIDS2017 release suffered from labeling or flow-construction defects, including clock-drift/time-window mismatches between attack execution logs and flow timestamps, IP/NAT role inversions, and benign background traffic mislabeled as attack (or attacks left as `BENIGN`).
  - **CICFlowMeter flow-construction bugs:** Incorrect TCP state/FIN-RST termination handling and flow timeout bugs split single connections into fragmented or zero-packet/meaningless flows that inherited incorrect labels.
  - **Duplicate/near-duplicate flows & identifier leakage:** `Source IP` and `Timestamp` are tightly coupled to specific attack tools and scheduled windows; keeping them as model features causes shortcut memorization (and our `cicids_pipeline.py` drops identifiers when `sanitize_session_features=True`).
- **Corrected/re-extracted releases (e.g., Engelen et al. 2021):**
  - **Cross-version incompatibility:** Re-extracted flows use modified TCP state and timeout rules, so feature distributions and row counts differ from the original `MachineLearningCVE` CSVs; mixing original and re-extracted files in train/test is invalid.
  - **Remaining single-day attack schedule:** Even with corrected timestamps and `Source IP`, each target family (`BruteForce`, `WebAttack`, `Bot`, `PortScan`) still occurs on only 1 capture day in CICIDS2017 (`n=1` day unit). **UNVERIFIED** whether re-extracted files resolve all `Infiltration`/`Heartbleed` or `WebAttack` edge cases without inspecting the acquired CSVs.

---

## (b) CSE-CIC-IDS2018 download and feature compatibility

### Download logistics (size, disk space, access method)
- **Access method:** Official AWS Open Data S3 bucket `s3://cse-cic-ids2018/` in region `ca-central-1`, accessible without an AWS account via `aws s3 ls s3://cse-cic-ids2018/ --no-sign-request --region ca-central-1` (or `aws s3 sync` / `aws s3 cp`). **UNVERIFIED** live bucket listing/availability because no network listing or download was executed.
- **Size and disk space:**
  - **Full bucket (raw PCAPs + logs + processed CSVs):** ~450 GB reported in public AWS/Kaggle references (**UNVERIFIED** exact current byte count; would require >500 GB free disk space if syncing everything).
  - **Processed CSVs only (`Processed Traffic Data for ML Algorithms/`):** Much smaller subset organized by capture day (10 attack dates documented: 2018-02-14..16, 2018-02-20..23, 2018-02-28, 2018-03-01..02). Exact compressed/uncompressed CSV size and per-day row counts are **UNVERIFIED** until a bucket listing is run (budget ~10–30 GB free space for CSVs + Parquet cache, **UNVERIFIED**).

### Feature compatibility with our codebase (`backend/ml/preprocessing/cicids_pipeline.py`)
Our model matrix currently uses:
1. **78 base numeric flow features** from CICIDS2017 (excluding `Destination Port` when `sanitize_session_features=True`).
2. **5 engineered protocol-invariant features** (`add_protocol_invariant_features`): `iat_cv`, `fwd_bwd_byte_ratio`, `is_well_known_port`, `is_registered_port`, `is_ephemeral_port`.
3. **9 host-window features** (`HostWindowAggregator`): `distinct_dst_ports_1m`, `syn_to_ack_ratio`, `flow_inter_arrival_variance`, `mean_bytes_per_flow`, `win_unique_dst_ports_60s`, `win_unique_dst_ips_60s`, `win_syn_only_ratio_60s`, `win_flow_rate_60s`, `suspicious_flows_60s`.

Compatibility across CICIDS2017 and CSE-CIC-IDS2018:

| Feature group | Computable on both datasets? | Notes & verification status |
|---|---|---|
| **Core CICFlowMeter statistical features** (duration, fwd/bwd packet/byte totals, packet-length min/max/mean/std, IAT summaries, rates, header lengths, TCP flag counts, active/idle, subflow, init window, down/up ratio, segment sizes) | **Candidate yes (with column-name mapping)** | CSE-CIC-IDS2018 uses abbreviated CICFlowMeter-V3 column names (e.g., `Tot Fwd Pkts`, `Flow Byts/s`) vs. CICIDS2017's verbose names (`Total Fwd Packets`, `Flow Bytes/s`). Exact 1-to-1 formula/unit/timeout equivalence (e.g., `Flow IAT`, `Init_Win_bytes`, `FIN/SYN/RST` semantics) is **UNVERIFIED** until both schemas are inspected or both PCAP sets are re-extracted with one pinned CICFlowMeter version. |
| **Protocol-invariant engineered features** (`iat_cv`, `fwd_bwd_byte_ratio`) | **Candidate yes** | Directly derived from `Flow IAT Std`/`Flow IAT Mean` and `Total Length of Fwd/Bwd Packets` once the underlying CSE column names and units are verified. |
| **Port-bucket flags** (`is_well_known_port`, `is_registered_port`, `is_ephemeral_port`) | **Candidate yes** | Derivable from `Destination Port` / CSE `Dst Port` (**UNVERIFIED** exact column name in CSE CSVs; raw port remains excluded from model inputs). |
| **Host-window features** (`HostWindowAggregator`: `win_*`, `distinct_dst_ports_1m`, `syn_to_ack_ratio`, `flow_inter_arrival_variance`, `mean_bytes_per_flow`, `suspicious_flows_60s`) | **No on current local 2017 CSVs; UNVERIFIED on CSE-CIC-IDS2018** | Requires both `Source IP` and per-flow `Timestamp`. Current local 2017 CSVs lack both (emitting all zeros). CSE-CIC-IDS2018 `Processed Traffic Data for ML Algorithms` CSVs omit `Source IP` in some day files and `Timestamp` formatting/presence varies by file (**UNVERIFIED** without inspecting actual CSE headers). Requires either `TrafficLabelling` 2017 + full-ID 2018 CSVs or PCAP re-extraction. |

### Recommended Phase 3 pre-experiment gate
Before running any Phase 3 model or cross-dataset experiment:
1. Run `aws s3 ls` (metadata only) to record exact CSE-CIC-IDS2018 CSV sizes and filenames.
2. Acquire only the processed CSVs (or re-extract from PCAPs if host-window features are in scope) and freeze a common column-mapping + schema-verification script.
3. Audit CSE per-day `Label` counts and cross-day duplicates before defining any Phase 3 splits.
