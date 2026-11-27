# Agent investigation results

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

