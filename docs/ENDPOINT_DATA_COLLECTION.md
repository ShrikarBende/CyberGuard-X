# Endpoint data collection for labeled Sysmon windows

This procedure creates a provenance-backed local dataset for endpoint evaluation. It does not label the existing public Sysmon corpus, and it does not create or claim any measured results. Do not use a production host or a VM containing real user data.

## Isolated VM procedure

1. Create a disposable Windows VM from a documented OS image and record its image/build, Sysmon version, VM identifier, UTC clock source, and snapshot identifier. Disable shared folders, clipboard, host credentials, and bridged networking. Use a host-only or otherwise isolated virtual network with no route to production. Take a clean VM snapshot before installing tools.
2. Install Sysmon from the official Sysinternals distribution and apply a version-controlled configuration that records the events consumed by this project: Event IDs 1 (process creation), 3 (network connection), 8 (remote thread), 10 (process access), 11 (file create), and 13 (registry value set). Keep the exact Sysmon binary version, configuration file, and SHA-256 hashes in the capture manifest. Review filtering rules before capture; filtered events are absent evidence, not evidence that behavior did not occur.
3. Capture a benign baseline first. Use a declared, repeatable local workload (for example, idle desktop plus a documented benign application workflow), with no Atomic Red Team tests running. Record start/end in UTC and the workload. Keep separate capture IDs for separate VM runs.
4. Revert to the clean snapshot before each attack capture. Select a specific Atomic Red Team test from its checked-in test definition, record the repository revision, test GUID, ATT&CK technique, prerequisites, operator, and execution result. Run only the selected test in the disposable VM. Prefer tests whose documented commands and effects have been reviewed and whose prerequisites can be satisfied without external network access. Record UTC execution start/end and Sysmon log coverage. Do not infer success from the test command returning alone; retain its result/output as provenance.
5. Export Sysmon event logs and the manifest to a controlled, access-restricted directory. Hash the original exports and manifest. Do not edit the source exports. Store one capture per directory and never concatenate events from different captures before feature-window construction.
6. Produce window rows using a documented, deterministic event ordering and windowing rule. Windows must not straddle capture boundaries. The current endpoint feature schema is the nine `FEATURE_NAMES` fields exported by `backend/ml/endpoint_dataset.py`. Preserve `capture_id` in every window row so future evaluation can split by capture. If event timestamps are missing, duplicated, or cannot be ordered reliably, mark the affected interval unusable rather than assigning a label.

## Labeling rules

- A benign label is allowed only for windows wholly inside a recorded benign interval where no Atomic test or other known attack simulation was running.
- An attack label is allowed only for a window wholly inside the recorded successful execution interval of the exact Atomic test. The test GUID and ATT&CK technique belong in a sidecar manifest; the loader's binary label does not claim a broader attack family.
- Exclude windows overlapping test setup, execution boundaries, cleanup, VM boot/revert, uncertain clock intervals, or unrelated activity. Do not force these windows into either class.
- Never label by filename, feature values, a heuristic risk score, or the detector's own prediction. A test that failed or whose execution interval cannot be established yields no attack-labeled windows.
- Preserve raw exports, manifests, and derived rows separately. A label correction creates a new version with a reason and operator; do not silently rewrite previous labels.
- Split and report by whole `capture_id`/VM run. Do not divide adjacent windows from one run across train and test. The current unsupervised endpoint model's existing evaluation path is separate; adding labeled rows does not make its stored metrics ground-truth validated until an independent held-out capture evaluation is run.

## Window CSV/JSONL format

Use exactly the nine numeric feature fields from `ml.endpoint_branch.FEATURE_NAMES`, plus an explicit `label` (`benign`/`attack` or `0`/`1`) and `capture_id`. JSONL may place the nine values inside a `features` object. The loader validates required fields, finite non-negative values, labels, and capture IDs; it does not derive labels or parse raw Sysmon event logs.

The required JSONL shape is shown below with placeholders only; it is not a sample event or labeled record:

```json
{"features":"<nine measured feature values>","label":"<manifest-derived benign or attack>","capture_id":"<operator-assigned-capture-id>"}
```

Validate a placed file without fitting a model:

```powershell
cd "D:\MAJOR PROJECT\backend"
python -c "from ml.endpoint_dataset import load_labeled_sysmon_windows; x,y,g=load_labeled_sysmon_windows(r'D:\path\to\windows.csv'); print({'rows':len(y),'features':x.shape[1],'capture_ids':len(set(g))})"
```

The command prints aggregate counts only. The loader is also tested with small test-only fixtures in `backend/tests/test_endpoint_dataset.py`; those fixtures are schema tests, not collected dataset records.
