# Network evaluation results

Reproduce this report and the five-seed network evaluation with `python scripts/run_network_eval.py`. The command runs the network baseline and renders this document from that run's JSON plus the saved auxiliary evaluation artifacts. Rendering alone does not run model evaluation.

The primary tables below report CICIDS2017 results. The final section records supplemental CSE-CIC-IDS2018 capture-day and cross-dataset measurements separately; those exploratory, bounded-sample results are not part of the five-seed baseline.

Artifact: [`network_baseline_20261127T113549Z.json`](../backend/ml/evaluation/results/network_baseline_20261127T113549Z.json) (run `20261127T113549Z`).
Dataset: `CICIDS2017`; raw source-file SHA-256 fingerprint: `9bb6edafdf07613af60d43f231e3d74b3fe9a7a308e4475d28446d326f72a1bd`; processed development sample SHA-256: `c31a87dde5b5696974cd48cd1206e236dfa29a729d52bbe08e1c0917821b6a22`.
Frozen holdout: `Monday-WorkingHours.pcap_ISCX.csv`; manifest SHA-256: `701a6fca14260729a21c47c9352e62af61526643b2ce44ba28bb000a0cb9b618`; status: frozen and untouched; no holdout rows were parsed or used for fitting, calibration, or scoring.
Session split: complete source CSV capture session; CICIDS2017 source files have no Timestamp column. for each family, every development source session containing that family is held out as test; those sessions are excluded from train and validation. one complete non-test source session is selected by GroupShuffleSplit using the recorded seed.
Seeds: `42, 101, 202, 303, 404`. Development sampling: stable feature-row hash modulo 100, threshold 15; applied only to development source sessions.
Decision policy: LightGBM multiclass with current repository class weights; confidence-only open-set score (1 - maximum class probability); threshold is the 95th percentile of known-only validation scores.
Confidence intervals: percentile bootstrap of seed-level metric means (10,000 resamples). Each seed’s interval uses stratified row bootstrap of binary decisions with known/unknown/benign supports fixed (2,000 resamples).

## Per-family unknown-review metrics

Values are the mean across seed runs with the 95% bootstrap interval across those seed-level estimates. The unknown class is the named family in the row; other test labels are treated as known only when that class was present in training.

| Attack family | Test sessions | Unknown support by seed | Precision | Recall | F1 | OSCR AUC | Known macro-F1 | Known FPR | Benign replay false-alert rate |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| DosDDoS | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, `Wednesday-workingHours.pcap_ISCX.csv` | 42: 48296; 101: 48296; 202: 48296; 303: 48296; 404: 48296 | 0.7849 (0.6062–0.8888) | 0.6286 (0.3531–0.7947) | 0.6804 (0.4068–0.8343) | 0.7243 (0.5015–0.8539) | 0.2666 (0.2499–0.2999) | 0.0728 (0.0604–0.0838) | 0.0728 (0.0604–0.0838) |
| PortScan | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 42: 13730; 101: 13730; 202: 13730; 303: 13730; 404: 13730 | 0.6185 (0.3638–0.8731) | 0.1364 (0.0080–0.3342) | 0.1880 (0.0154–0.4324) | 0.7712 (0.6579–0.8634) | 0.2293 (0.2093–0.2493) | 0.0223 (0.0021–0.0442) | 0.0223 (0.0021–0.0442) |
| BruteForce | `Tuesday-WorkingHours.pcap_ISCX.csv` | 42: 1379; 101: 1379; 202: 1379; 303: 1379; 404: 1379 | 0.1262 (0.0341–0.2182) | 0.3373 (0.0094–0.7269) | 0.1320 (0.0161–0.2479) | 0.6374 (0.3455–0.9296) | 0.2078 (0.1955–0.2293) | 0.0371 (0.0050–0.0708) | 0.0371 (0.0050–0.0708) |
| WebAttack | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 42: 320; 101: 320; 202: 320; 303: 320; 404: 320 | 0.0306 (0.0130–0.0493) | 0.0494 (0.0144–0.0844) | 0.0337 (0.0111–0.0562) | 0.6614 (0.3684–0.9484) | 0.2456 (0.2075–0.2897) | 0.0178 (0.0044–0.0339) | 0.0178 (0.0044–0.0339) |
| Bot | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 42: 305; 101: 305; 202: 305; 303: 305; 404: 305 | 0.0146 (0.0000–0.0438) | 0.0649 (0.0000–0.1948) | 0.0239 (0.0000–0.0716) | 0.6130 (0.4058–0.7790) | 0.2731 (0.2297–0.3165) | 0.0196 (0.0046–0.0349) | 0.0196 (0.0046–0.0349) |

## Known-class classifier metrics

Per-class values are one-vs-rest precision, recall, F1, and average precision (AUPRC); macro values, Cohen's kappa, and MCC are aggregated across the five seeds with percentile bootstrap 95% confidence intervals. Metrics are reported for the in-sample training split, known-only validation split, and known-only test split in every family fold. Training metrics are diagnostics, not generalization estimates. The held-out unknown family is excluded from closed-set classifier metrics. AUPRC is `n/a` when a class has no positive rows; macro AUPRC averages classes with positive support.

### Aggregate metrics by split

| Held-out family | Split | Macro precision | Macro recall | Macro F1 | Macro AUPRC | Cohen's kappa | MCC |
|---|---|---:|---:|---:|---:|---:|---:|
| DosDDoS | Train (in-sample) | 0.9858 (0.9694–0.9988) | 0.9999 (0.9998–0.9999) | 0.9923 (0.9815–0.9994) | 0.9992 (0.9976–1.0000) | 0.9965 (0.9952–0.9977) | 0.9965 (0.9952–0.9977) |
| DosDDoS | Validation | 0.2500 (0.2500–0.2500) | 0.2497 (0.2492–0.2500) | 0.2498 (0.2496–0.2500) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |
| DosDDoS | Known-only test | 0.2500 (0.2500–0.2500) | 0.2498 (0.2497–0.2499) | 0.2499 (0.2498–0.2500) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |
| PortScan | Train (in-sample) | 0.9368 (0.8977–0.9715) | 0.9997 (0.9994–0.9999) | 0.9618 (0.9349–0.9849) | 0.9942 (0.9888–0.9992) | 0.9946 (0.9901–0.9985) | 0.9946 (0.9902–0.9985) |
| PortScan | Validation | 0.2835 (0.2340–0.3284) | 0.2497 (0.2225–0.2748) | 0.2406 (0.2064–0.2749) | 0.9751 (0.9519–0.9982) | 0.2078 (0.0321–0.3835) | 0.4371 (0.2875–0.5352) |
| PortScan | Known-only test | 0.2100 (0.2000–0.2300) | 0.2087 (0.1986–0.2287) | 0.2093 (0.1993–0.2293) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |
| BruteForce | Train (in-sample) | 0.8676 (0.8101–0.9323) | 0.9988 (0.9981–0.9994) | 0.9064 (0.8605–0.9559) | 0.9809 (0.9712–0.9918) | 0.9893 (0.9830–0.9955) | 0.9893 (0.9832–0.9955) |
| BruteForce | Validation | 0.1794 (0.1121–0.2467) | 0.1989 (0.1769–0.2254) | 0.1670 (0.1275–0.2095) | 0.9344 (0.8821–0.9867) | 0.0289 (-0.0016–0.0709) | 0.0875 (-0.0090–0.1736) |
| BruteForce | Known-only test | 0.2100 (0.2000–0.2300) | 0.2058 (0.1912–0.2285) | 0.2078 (0.1955–0.2293) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |
| WebAttack | Train (in-sample) | 0.8839 (0.8314–0.9478) | 0.9980 (0.9955–0.9996) | 0.9100 (0.8563–0.9614) | 0.9789 (0.9682–0.9904) | 0.9781 (0.9489–0.9957) | 0.9788 (0.9511–0.9957) |
| WebAttack | Validation | 0.2184 (0.1614–0.2853) | 0.2001 (0.1761–0.2299) | 0.1857 (0.1546–0.2203) | 0.9278 (0.8617–0.9938) | 0.0941 (0.0274–0.1609) | 0.2531 (0.2386–0.2673) |
| WebAttack | Known-only test | 0.2100 (0.2000–0.2300) | 0.2080 (0.1952–0.2295) | 0.2090 (0.1976–0.2297) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |
| Bot | Train (in-sample) | 0.9514 (0.9255–0.9789) | 0.9994 (0.9992–0.9997) | 0.9709 (0.9542–0.9878) | 1.0000 (0.9999–1.0000) | 0.9954 (0.9928–0.9977) | 0.9954 (0.9931–0.9977) |
| Bot | Validation | 0.2574 (0.2267–0.2856) | 0.2108 (0.1876–0.2340) | 0.1836 (0.1515–0.2209) | 0.9326 (0.8676–0.9920) | 0.0546 (0.0022–0.1267) | 0.1635 (0.0445–0.2932) |
| Bot | Known-only test | 0.2100 (0.2000–0.2300) | 0.2096 (0.1995–0.2298) | 0.2098 (0.1997–0.2299) | 1.0000 (1.0000–1.0000) | 0.0000 (0.0000–0.0000) | n/a |

### Per-class metrics by split

Support is listed by seed; metric cells show the seed mean and 95% seed-bootstrap interval.

| Held-out family | Split | Known class | Precision | Recall | F1 | AUPRC | Support by seed |
|---|---|---|---:|---:|---:|---:|---|
| DosDDoS | Train (in-sample) | BENIGN | 1.0000 (1.0000–1.0000) | 0.9994 (0.9991–0.9997) | 0.9997 (0.9995–0.9999) | 1.0000 (1.0000–1.0000) | 42: 53997; 101: 59193; 202: 53997; 303: 52618; 404: 53997 |
| DosDDoS | Train (in-sample) | Bot | 0.8705 (0.8093–0.9318) | 1.0000 (1.0000–1.0000) | 0.9296 (0.8946–0.9647) | 0.9919 (0.9841–0.9998) | 42: n/a; 101: 123; 202: n/a; 303: 157; 404: n/a |
| DosDDoS | Train (in-sample) | BruteForce | 1.0000 (1.0000–1.0000) | 1.0000 (1.0000–1.0000) | 1.0000 (1.0000–1.0000) | 1.0000 (1.0000–1.0000) | 42: 537; 101: 555; 202: 537; 303: n/a; 404: 537 |
| DosDDoS | Train (in-sample) | PortScan | 0.9954 (0.9949–0.9960) | 1.0000 (1.0000–1.0000) | 0.9977 (0.9974–0.9980) | 0.9998 (0.9998–0.9999) | 42: 5342; 101: n/a; 202: 5342; 303: 7060; 404: 5342 |
| DosDDoS | Train (in-sample) | WebAttack | 0.9988 (0.9964–1.0000) | 1.0000 (1.0000–1.0000) | 0.9994 (0.9982–1.0000) | 1.0000 (1.0000–1.0000) | 42: 124; 101: 129; 202: 124; 303: 165; 404: 124 |
| DosDDoS | Validation | BENIGN | 1.0000 (1.0000–1.0000) | 0.9987 (0.9967–0.9999) | 0.9994 (0.9983–1.0000) | 1.0000 (1.0000–1.0000) | 42: 25600; 101: 17353; 202: 25600; 303: 62059; 404: 25600 |
| DosDDoS | Validation | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: n/a; 101: 0; 202: n/a; 303: 0; 404: n/a |
| DosDDoS | Validation | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: n/a; 404: 0 |
| DosDDoS | Validation | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: n/a; 202: 0; 303: 0; 404: 0 |
| DosDDoS | Validation | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| DosDDoS | Known-only test | BENIGN | 1.0000 (1.0000–1.0000) | 0.9993 (0.9987–0.9997) | 0.9996 (0.9994–0.9998) | 1.0000 (1.0000–1.0000) | 42: 74837; 101: 74837; 202: 74837; 303: 74837; 404: 74837 |
| DosDDoS | Known-only test | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: n/a; 101: 0; 202: n/a; 303: 0; 404: n/a |
| DosDDoS | Known-only test | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: n/a; 404: 0 |
| DosDDoS | Known-only test | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: n/a; 202: 0; 303: 0; 404: 0 |
| DosDDoS | Known-only test | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Train (in-sample) | BENIGN | 1.0000 (1.0000–1.0000) | 0.9986 (0.9974–0.9995) | 0.9993 (0.9987–0.9997) | 1.0000 (1.0000–1.0000) | 42: 52203; 101: 52203; 202: 47206; 303: 53006; 404: 47944 |
| PortScan | Train (in-sample) | Bot | 0.7427 (0.5792–0.8822) | 1.0000 (1.0000–1.0000) | 0.8402 (0.7226–0.9374) | 0.9716 (0.9443–0.9966) | 42: 76; 101: 76; 202: 78; 303: 101; 404: 74 |
| PortScan | Train (in-sample) | BruteForce | 0.9822 (0.9649–0.9994) | 1.0000 (1.0000–1.0000) | 0.9909 (0.9821–0.9997) | 1.0000 (1.0000–1.0000) | 42: 346; 101: 346; 202: 351; 303: 455; 404: 333 |
| PortScan | Train (in-sample) | DosDDoS | 0.9964 (0.9924–0.9993) | 0.9999 (0.9998–1.0000) | 0.9982 (0.9961–0.9996) | 0.9999 (0.9999–1.0000) | 42: 7295; 101: 7295; 202: 12284; 303: 6332; 404: 11649 |
| PortScan | Train (in-sample) | WebAttack | 0.9614 (0.9411–0.9817) | 1.0000 (1.0000–1.0000) | 0.9802 (0.9696–0.9908) | 1.0000 (1.0000–1.0000) | 42: 80; 101: 80; 202: 81; 303: 106; 404: n/a |
| PortScan | Validation | BENIGN | 0.7685 (0.5818–0.9553) | 0.9876 (0.9719–0.9977) | 0.8483 (0.7227–0.9738) | 0.9733 (0.9446–0.9969) | 42: 13494; 101: 13494; 202: 36271; 303: 61343; 404: 23103 |
| PortScan | Validation | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Validation | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Validation | DosDDoS | 0.5988 (0.1993–0.9983) | 0.2108 (0.0387–0.3829) | 0.3049 (0.0648–0.5449) | 0.9614 (0.9142–0.9977) | 42: 19175; 101: 19175; 202: 0; 303: 29121; 404: 0 |
| PortScan | Validation | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: n/a |
| PortScan | Known-only test | BENIGN | 1.0000 (1.0000–1.0000) | 0.9937 (0.9928–0.9946) | 0.9968 (0.9964–0.9973) | 1.0000 (1.0000–1.0000) | 42: 17353; 101: 17353; 202: 17353; 303: 17353; 404: 17353 |
| PortScan | Known-only test | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Known-only test | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Known-only test | DosDDoS | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| PortScan | Known-only test | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: n/a |
| BruteForce | Train (in-sample) | BENIGN | 0.9999 (0.9998–1.0000) | 0.9949 (0.9923–0.9976) | 0.9974 (0.9961–0.9987) | 0.9998 (0.9997–0.9999) | 42: 47407; 101: 47407; 202: 42512; 303: 46530; 404: 41532 |
| BruteForce | Train (in-sample) | Bot | 0.3715 (0.2529–0.4901) | 1.0000 (1.0000–1.0000) | 0.5290 (0.4037–0.6542) | 0.8852 (0.8565–0.9042) | 42: 88; 101: 88; 202: n/a; 303: 122; 404: 90 |
| BruteForce | Train (in-sample) | DosDDoS | 0.9948 (0.9907–0.9990) | 0.9994 (0.9991–0.9998) | 0.9971 (0.9949–0.9994) | 1.0000 (0.9999–1.0000) | 42: 8435; 101: 8435; 202: 13547; 303: 7703; 404: 14237 |
| BruteForce | Train (in-sample) | PortScan | 0.9949 (0.9933–0.9974) | 0.9996 (0.9992–1.0000) | 0.9972 (0.9963–0.9986) | 0.9998 (0.9997–0.9999) | 42: 3977; 101: 3977; 202: 3851; 303: 5516; 404: 4047 |
| BruteForce | Train (in-sample) | WebAttack | 0.8523 (0.7706–0.9325) | 1.0000 (1.0000–1.0000) | 0.9173 (0.8657–0.9625) | 0.9968 (0.9904–1.0000) | 42: 93; 101: 93; 202: 90; 303: 129; 404: 94 |
| BruteForce | Validation | BENIGN | 0.7143 (0.4850–0.9436) | 0.9446 (0.8842–0.9953) | 0.7846 (0.6371–0.9321) | 0.9218 (0.8472–0.9888) | 42: 13494; 101: 13494; 202: 25600; 303: 61343; 404: 36271 |
| BruteForce | Validation | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: n/a; 303: 0; 404: 0 |
| BruteForce | Validation | DosDDoS | 0.1326 (0.0000–0.3788) | 0.0001 (0.0000–0.0003) | 0.0002 (0.0000–0.0007) | 0.9115 (0.8731–0.9384) | 42: 19175; 101: 19175; 202: 0; 303: 29121; 404: 0 |
| BruteForce | Validation | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| BruteForce | Validation | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| BruteForce | Known-only test | BENIGN | 1.0000 (1.0000–1.0000) | 0.9791 (0.9553–0.9948) | 0.9893 (0.9769–0.9974) | 1.0000 (1.0000–1.0000) | 42: 62059; 101: 62059; 202: 62059; 303: 62059; 404: 62059 |
| BruteForce | Known-only test | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: n/a; 303: 0; 404: 0 |
| BruteForce | Known-only test | DosDDoS | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| BruteForce | Known-only test | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| BruteForce | Known-only test | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| WebAttack | Train (in-sample) | BENIGN | 0.9999 (0.9999–1.0000) | 0.9911 (0.9792–0.9981) | 0.9955 (0.9894–0.9991) | 0.9999 (0.9999–1.0000) | 42: 49189; 101: 49189; 202: 45018; 303: 49041; 404: 44305 |
| WebAttack | Train (in-sample) | Bot | 0.3476 (0.1594–0.5103) | 1.0000 (1.0000–1.0000) | 0.4824 (0.2339–0.6756) | 0.8688 (0.8326–0.9175) | 42: 74; 101: 74; 202: n/a; 303: 97; 404: 75 |
| WebAttack | Train (in-sample) | BruteForce | 0.9525 (0.9034–0.9942) | 1.0000 (1.0000–1.0000) | 0.9749 (0.9485–0.9971) | 1.0000 (1.0000–1.0000) | 42: 335; 101: 335; 202: 326; 303: 437; 404: 340 |
| WebAttack | Train (in-sample) | DosDDoS | 0.9946 (0.9904–0.9989) | 0.9992 (0.9986–0.9998) | 0.9969 (0.9945–0.9993) | 0.9999 (0.9998–1.0000) | 42: 7069; 101: 7069; 202: 11412; 303: 6075; 404: 11898 |
| WebAttack | Train (in-sample) | PortScan | 0.9947 (0.9924–0.9974) | 0.9996 (0.9992–0.9999) | 0.9971 (0.9958–0.9985) | 0.9998 (0.9997–0.9999) | 42: 3333; 101: 3333; 202: 3244; 303: 4350; 404: 3382 |
| WebAttack | Validation | BENIGN | 0.7891 (0.6373–0.9408) | 0.9310 (0.8805–0.9815) | 0.8426 (0.7553–0.9328) | 0.9357 (0.8592–0.9965) | 42: 13494; 101: 13494; 202: 25600; 303: 61343; 404: 36271 |
| WebAttack | Validation | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: n/a; 303: 0; 404: 0 |
| WebAttack | Validation | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| WebAttack | Validation | DosDDoS | 0.2528 (0.0178–0.6301) | 0.0198 (0.0000–0.0592) | 0.0360 (0.0001–0.1077) | 0.8663 (0.7698–0.9561) | 42: 19175; 101: 19175; 202: 0; 303: 29121; 404: 0 |
| WebAttack | Validation | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| WebAttack | Known-only test | BENIGN | 1.0000 (1.0000–1.0000) | 0.9898 (0.9761–0.9979) | 0.9948 (0.9877–0.9990) | 1.0000 (1.0000–1.0000) | 42: 23103; 101: 23103; 202: 23103; 303: 23103; 404: 23103 |
| WebAttack | Known-only test | Bot | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: n/a; 303: 0; 404: 0 |
| WebAttack | Known-only test | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| WebAttack | Known-only test | DosDDoS | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| WebAttack | Known-only test | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Train (in-sample) | BENIGN | 0.9999 (0.9998–1.0000) | 0.9982 (0.9974–0.9990) | 0.9991 (0.9987–0.9995) | 1.0000 (1.0000–1.0000) | 42: 49076; 101: 49076; 202: 44140; 303: 48890; 404: 45018 |
| Bot | Train (in-sample) | BruteForce | 0.9922 (0.9837–0.9982) | 1.0000 (1.0000–1.0000) | 0.9961 (0.9918–0.9991) | 1.0000 (1.0000–1.0000) | 42: 338; 101: 338; 202: 343; 303: 443; 404: 326 |
| Bot | Train (in-sample) | DosDDoS | 0.9948 (0.9909–0.9981) | 0.9993 (0.9987–0.9998) | 0.9970 (0.9949–0.9989) | 0.9999 (0.9999–1.0000) | 42: 7141; 101: 7141; 202: 12020; 303: 6156; 404: 11412 |
| Bot | Train (in-sample) | PortScan | 0.9962 (0.9948–0.9978) | 0.9997 (0.9994–0.9999) | 0.9979 (0.9972–0.9988) | 0.9998 (0.9997–0.9999) | 42: 3367; 101: 3367; 202: 3417; 303: 4408; 404: 3244 |
| Bot | Train (in-sample) | WebAttack | 0.7177 (0.6180–0.8173) | 1.0000 (1.0000–1.0000) | 0.8308 (0.7624–0.8989) | 1.0000 (1.0000–1.0000) | 42: 78; 101: 78; 202: 80; 303: 103; 404: n/a |
| Bot | Validation | BENIGN | 0.7282 (0.5202–0.9363) | 0.9666 (0.9045–0.9983) | 0.8039 (0.6801–0.9276) | 0.9293 (0.8671–0.9879) | 42: 13494; 101: 13494; 202: 36271; 303: 61343; 404: 23103 |
| Bot | Validation | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Validation | DosDDoS | 0.5088 (0.1190–0.8986) | 0.0375 (0.0003–0.1078) | 0.0644 (0.0006–0.1837) | 0.8929 (0.7422–0.9807) | 42: 19175; 101: 19175; 202: 0; 303: 29121; 404: 0 |
| Bot | Validation | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Validation | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: n/a |
| Bot | Known-only test | BENIGN | 1.0000 (1.0000–1.0000) | 0.9982 (0.9974–0.9989) | 0.9991 (0.9987–0.9995) | 1.0000 (1.0000–1.0000) | 42: 25600; 101: 25600; 202: 25600; 303: 25600; 404: 25600 |
| Bot | Known-only test | BruteForce | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Known-only test | DosDDoS | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Known-only test | PortScan | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: 0 |
| Bot | Known-only test | WebAttack | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | 0.0000 (0.0000–0.0000) | n/a | 42: 0; 101: 0; 202: 0; 303: 0; 404: n/a |

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
## Step C: Binary attack-vs-benign leave-one-capture-day-out evaluation

**Protocol:** binary attack-vs-benign leave-one-capture-day-out. Scope: CICIDS2017 development scope (4 held-out day units: Tue, Wed, Thu, Fri). Positive class: any non-BENIGN label. Threshold: p95 of training BENIGN row scores (default threshold, unchanged).

**Step C constraints:** measurement only; no model change; no training/split change; no threshold tuning; no feature engineering change; Monday holdout file never loaded.

Artifact: [`locd_binary_eval_20261127T122308Z.json`](../backend/ml/evaluation/results/locd_binary_eval_20261127T122308Z.json) (run `20261127T122308Z`).
Dataset: `CICIDS2017`; SHA-256: `9bb6edafdf07613af60d43f231e3d74b3fe9a7a308e4475d28446d326f72a1bd`.
Holdout: `Monday-WorkingHours.pcap_ISCX.csv` — frozen and untouched; never loaded for scoring or fitting.

### Aggregate metrics — paired capture-day bootstrap

Bootstrap: paired over 4 held-out capture-day units, 10,000 resamples. Mean and 95% CI.

| Metric | Mean (95% CI) |
|---|---:|
| Binary precision | 0.4082 (0.0548–0.7617) |
| Binary recall    | 0.5260 (0.2485–0.8085) |
| Binary F1        | 0.3150 (0.0910–0.5724) |
| Binary AUPRC     | 0.4162 (0.0520–0.7805) |
| FPR              | 0.0823 (0.0514–0.1282) |

### Per held-out day results

| Held-out day | Precision | Recall | F1 | AUPRC | FPR | Benign rows | Attack rows | Test rows | Families present |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Tuesday | 0.0758 | 0.2526 | 0.1166 | 0.0744 | 0.0715 | 62,046 | 1,441 | 63,487 | BruteForce |
| Wednesday | 0.6389 | 0.2443 | 0.3535 | 0.7035 | 0.0633 | 62,581 | 28,704 | 91,285 | DosDDoS |
| Thursday | 0.0338 | 0.9939 | 0.0655 | 0.0296 | 0.1498 | 61,758 | 326 | 62,084 | WebAttack |
| Friday | 0.8844 | 0.6134 | 0.7244 | 0.8574 | 0.0447 | 59,423 | 33,144 | 92,567 | Bot, PortScan, DosDDoS |

### Per-family recall (descriptive only, n=1 capture day unit per family)

**descriptive only, n=1 capture day unit per family; not used for any accept/reject decision** Per-family recall without per-day FPR is uninterpretable on its own; each row pairs the family's recall with that held-out day's overall binary FPR, binary precision, and benign row count. With n=1 held-out day per family, per-family generalization cannot be reliably estimated.

| Family | Held-out day | Attack rows | Recall | Day FPR | Day precision | Day benign rows | Note |
|---|---|---:|---:|---:|---:|---:|---|
| Bot | Friday | 306 | 0.0000 | 0.0447 | 0.8844 | 59,423 | descriptive, n=1 capture day unit |
| BruteForce | Tuesday | 1,441 | 0.2526 | 0.0715 | 0.0758 | 62,046 | descriptive, n=1 capture day unit |
| DosDDoS | Wednesday | 28,704 | 0.2443 | 0.0633 | 0.6389 | 62,581 | descriptive, n=1 capture day unit |
| DosDDoS | Friday | 19,177 | 0.9986 | 0.0447 | 0.8844 | 59,423 | descriptive, n=1 capture day unit |
| PortScan | Friday | 13,661 | 0.0863 | 0.0447 | 0.8844 | 59,423 | descriptive, n=1 capture day unit |
| WebAttack | Thursday | 326 | 0.9939 | 0.1498 | 0.0338 | 61,758 | descriptive, n=1 capture day unit |

## CSE-CIC-IDS2018 ingestion and transfer evaluation

Generated local artifacts: `backend/ml/evaluation/results/cse_capture_day.json` and `backend/ml/evaluation/results/cross_dataset.json`. Reproduce from `backend/` with:

```powershell
python -m ml.evaluation.cross_dataset --mode cse-capture-day --output ml/evaluation/results/cse_capture_day.json
python -m ml.evaluation.cross_dataset --mode cross-dataset --output ml/evaluation/results/cross_dataset.json
```

Both runs used seed 42. CSE-CIC-IDS2018 CSV ingestion parses feature strings strictly, replaces infinities with NaN, and drops rows with missing/non-finite required numeric values before validation. It dropped **13,484** rows total (4,050 on 2018-03-02; 5,610 on 2018-02-22; 3,824 on 2018-02-14). The adapter retains every non-BENIGN row and deterministic-reservoir-samples up to **50,000 BENIGN rows per capture**, using a fixed seed derived from seed 42 and the capture filename. Feature matrices use float32. Since some attack classes alone exceed 50,000, the cap applies to BENIGN rows and total rows can exceed 50,000.

The cross-dataset run reads the existing deduplicated CICIDS2017 Parquet cache in batches and uses a deterministic feature-hash priority sample stratified by label, capped at 50,000 rows per label (seed 42). It retained 163,241 of 2,496,702 CICIDS2017 rows. This bounded sample is part of the reported protocol. It is not the full CICIDS2017 population.

### CSE-CIC-IDS2018 binary capture-day evaluation

Protocol: binary attack-vs-benign leave-one-capture-day-out, **n=3 capture days**. The aggregate is the unweighted mean of held-out-day macro-F1; family recalls are descriptive and have only one supporting capture day where present.

| Metric | Value |
|---|---:|
| Mean capture-day macro-F1 | 0.36788369959339545 |
| Capture-day macro-F1 standard deviation | 0.18663244080542973 |
| Source rows | 3,145,725 |
| Rows dropped for non-finite/missing numeric features | 13,484 |
| Cleaned rows | 3,132,241 |
| Attack rows retained | 667,496 |
| BENIGN rows retained | 150,000 |
| Total rows retained after sampling | 817,496 |

| Family | Capture days | Files | Cleaned attack flows | Recall | Held-out capture-day units (n) | Support |
|---|---|---:|---:|---:|---:|---:|
| Bot | 2018-03-02 | 1 | 286,191 | 0.44703013022771504 | 1 | 286,191 |
| WebAttack | 2018-02-22 | 1 | 362 | 0.0 | 1 | 362 |
| BruteForce | 2018-02-14 | 1 | 380,943 | 0.0 | 1 | 380,943 |
| DoS/DDoS | none | 0 | 0 | n/a | 0 | 0 |
| Infiltration | none | 0 | 0 | n/a | 0 | 0 |
| PortScan | none | 0 | 0 | n/a | 0 | 0 |

| Held-out capture day | Macro-F1 | Accuracy | Train rows | Test rows |
|---|---:|---:|---:|---:|
| 2018-02-14 | 0.10395310830086206 | 0.11601302260391745 | 386,553 | 430,943 |
| 2018-02-22 | 0.49812151833139007 | 0.9925141972121838 | 767,134 | 50,362 |
| 2018-03-02 | 0.5015764721479343 | 0.5285328875549911 | 481,305 | 336,191 |

### CICIDS2017 ↔ CSE-CIC-IDS2018 transfer

Protocol: train on one dataset, test on the other, seed 42. CICIDS2017 is label-stratified and capped at 50,000 rows per label; CSE uses all attack rows plus up to 50,000 BENIGN rows per capture. The model uses the 80 common canonical numeric flow features listed in the JSON. CICIDS2017 `DosDDoS` and `PortScan` are excluded because those labels are absent from the three supplied CSE captures. These results therefore cover the four shared labels only and do not estimate transfer for the excluded families.

| Direction | Macro-F1 | Accuracy | Train rows | Test rows | Excluded train rows | Excluded test rows |
|---|---:|---:|---:|---:|---:|---:|
| CICIDS2017 → CSE-CIC-IDS2018 | 0.08537530967418447 | 0.18219294039359213 | 63,241 | 817,496 | 100,000 | 0 |
| CSE-CIC-IDS2018 → CICIDS2017 | 0.2571008570815823 | 0.7829572587403741 | 817,496 | 63,241 | 0 | 100,000 |

| Shared family | CICIDS2017 source rows | CSE cleaned rows | CICIDS2017 → CSE recall | CSE → CICIDS2017 recall |
|---|---:|---:|---:|---:|
| BENIGN | 2,071,726 | 2,464,745 | 0.9928266666666666 | 0.98352 |
| Bot | 1,948 | 286,191 | 4.542420970610536e-05 | 0.060574948665297744 |
| BruteForce | 9,150 | 380,943 | 0.0 | 0.024153005464480876 |
| WebAttack | 2,143 | 362 | 0.013812154696132596 | 0.0 |

The CSE attack coverage is one capture day per observed family, so capture-day and per-family results are descriptive. The cross-dataset scores use a bounded CICIDS2017 sample and only labels shared by the selected files; they should not be interpreted as full-population performance or as evidence for DoS/DDoS, Infiltration, or PortScan transfer.
