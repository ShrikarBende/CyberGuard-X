# Model Artifact Security

**Branch:** `phase-4-model-security`  
**Last updated:** 2026-11-27  
**Status:** Implemented (Phase 4, Items 1–5); safe-format conversion is documented here as future work only — no conversions were performed.

---

## 1. What signing protects

Each model bundle (`.pkl` / `.joblib`) is accompanied by a manifest file
(`<bundle>.manifest.json`) that records:

| Field | Description |
|---|---|
| `sha256` | SHA-256 hex digest of the bundle file bytes |
| `model_version` | Semantic version string recorded at training time |
| `data_hash` | Hash of the dataset used to train the bundle |
| `git_commit` | Git HEAD SHA at training time (may be `unknown` if not in a repo) |
| `config` | Snapshot of model hyper-parameters / training config |
| `metrics` | Evaluation metrics recorded at training time |
| `created_at` | ISO-8601 UTC timestamp |
| `hmac_sha256` | HMAC-SHA256 of the manifest body, keyed with `ARTIFACT_HMAC_KEY` |

Before any `joblib.load()` call the application:

1. Reads the companion manifest.
2. Re-computes the SHA-256 of the file on disk and compares it to `sha256`
   in the manifest.  A mismatch means the file has been tampered with or
   corrupted since it was signed.
3. Verifies the HMAC-SHA256 of the manifest body using `ARTIFACT_HMAC_KEY`.
   A mismatch means the manifest itself was altered after signing.
4. Refuses to load — raising `RuntimeError` with a clear message — if either
   check fails, unless `ALLOW_UNSIGNED_MODELS=true` is set (see §4).

This covers:

* **File-system injection / replacement attacks** — an attacker who can write
  to `backend/saved_models/` but does not know the HMAC key cannot create a
  validly-signed replacement bundle.
* **Offline tampering** — a bundle modified between a training run and
  deployment will be caught by the SHA-256 check even before the HMAC check.
* **Manifest substitution** — swapping a manifest from a different (but
  legitimately signed) bundle is caught because the HMAC is computed over the
  manifest body which includes the bundle name, SHA-256, and version.
* **Partial writes / truncation** — a truncated or zero-padded bundle will
  produce a different SHA-256 and be rejected.
* **Registry rollback integrity** — the registry (`registry.json`) activates a
  version only after re-verifying its signature; a rollback to a known-good
  version is therefore also protected.

---

## 2. What signing does NOT protect

> [!CAUTION]
> These residual risks are inherent to symmetric-key HMAC signing.
> Understand them before relying on this scheme in a high-threat environment.

| Threat | Why not covered |
|---|---|
| **Attacker who knows `ARTIFACT_HMAC_KEY`** | They can produce any bundle, sign it correctly, and deploy it. The key must be kept secret; rotate it immediately if compromised (see §3). |
| **Compromised training machine** | A build server or Jupyter environment that is itself malicious can produce a poisoned bundle and sign it legitimately with the real key. Signing only proves "this was signed by whoever holds the key", not "this was trained on the expected data with the expected code". |
| **Insider with file-system write access and key access** | Equivalent to the above. Access controls on the key (environment secrets, secrets manager) are the primary mitigation. |
| **Adversarial training data (data poisoning)** | If the training data contains injected rows, the resulting model is faithfully signed but produces wrong predictions. See `docs/PHASE4_AUDIT.md §6` for the analyst-feedback poisoning exposure. |
| **Supply-chain attack on dependencies** | A compromised `lightgbm`, `scikit-learn`, or `joblib` package could tamper with bundle contents in memory after the hash check. Keep dependencies pinned and audited. |
| **GPU / hardware-level side channels** | Out of scope for this scheme. |
| **In-flight tampering of the HTTP response** | The API serving predictions is TLS-terminated; the bundle files are never transmitted over the wire in normal operation. |

---

## 3. Key management and rotation

### Generating a key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Store the output in your secrets manager (e.g. GitHub Actions secret,
HashiCorp Vault, AWS Secrets Manager) and inject it as `ARTIFACT_HMAC_KEY`
in the runtime environment.  **Never commit it to version control.**

### Setting the key

Add to your `.env` (never committed) or deployment environment:

```
ARTIFACT_HMAC_KEY=<64-hex-char string>
```

The application reads this at startup via `app.core.config.settings.ARTIFACT_HMAC_KEY`.
If the variable is an empty string the application starts but all load
attempts will fail with a clear error (unless `ALLOW_UNSIGNED_MODELS=true`).

### Rotating the key

1. **Generate** a new key (see above).
2. **Re-sign all bundles** with the new key _before_ updating the application
   environment:
   ```bash
   ARTIFACT_HMAC_KEY=<new-key> python scripts/sign_existing_models.py
   ```
   This script iterates over every bundle in `backend/saved_models/`, reads or
   creates a manifest, and writes a fresh HMAC signature using the supplied key.
   Inspect the output — it lists every file it signs and reports any it skips.
3. **Verify** the new signatures in a staging environment before deploying to
   production.
4. **Update `ARTIFACT_HMAC_KEY`** in every deployment environment / secrets
   store to the new key.
5. **Restart the application** so it picks up the new key.

> [!WARNING]
> If you update the key in the environment _before_ re-signing the bundles,
> every model load will fail until step 2 is completed.
> Always re-sign first.

### Key scoping

There is currently a single `ARTIFACT_HMAC_KEY` shared across all bundle types.
In a higher-security environment, consider per-model-type keys; this would
require storing the key name alongside the HMAC in the manifest.

---

## 4. `ALLOW_UNSIGNED_MODELS` flag

| Setting | Behaviour |
|---|---|
| `ALLOW_UNSIGNED_MODELS=false` (default) | Any load path that finds a missing, mismatched, or absent manifest raises `RuntimeError` and refuses to proceed. |
| `ALLOW_UNSIGNED_MODELS=true` | Load proceeds, but a **loud `WARNING`** is emitted on every single load. Intended for the transition period while existing bundles are being signed, or for local development without a signing key. |

**Never enable `ALLOW_UNSIGNED_MODELS=true` in production.**

The test suite (`backend/tests/conftest.py`) sets `ALLOW_UNSIGNED_MODELS=true`
globally so that existing unsigned bundles in `backend/saved_models/` do not
break unrelated tests.  Individual security tests override this with
`monkeypatch.setenv("ALLOW_UNSIGNED_MODELS", "false")` to test strict
enforcement.

---

## 5. Safe-format migration candidates

Converting bundles to format-safe alternatives (ONNX, `safetensors`, JSON
weights) would eliminate the entire class of pickle-based arbitrary-code
execution risks.  **No conversions were performed in Phase 4.**  The table
below documents feasibility and obstacles found during the Phase 4 audit.

| Bundle | Current format | Safe-format candidate | Feasibility | Obstacles / notes |
|---|---|---|---|---|
| `cicids2017_medium_lightgbm.bundle.pkl` (and `cicids2017_lightgbm.bundle.pkl`) | joblib pickle | LightGBM native `.txt` / `.json` for the booster; `skl2onnx` / `onnxmltools` for the `IsolationForest` anomaly detector | **Partial — booster feasible; IF obstacle** | LightGBM's `Booster.save_model()` outputs a human-readable text format with no executable code.  The `IsolationForest` companion in the same bundle uses `ExtraTreeRegressor` internals; no zero-dependency JSON representation exists — `skl2onnx`/`onnxmltools` required (UNVERIFIED installed). `sklearn` version pinning essential for deterministic ONNX output. |
| `endpoint_behavior.bundle.pkl` | joblib pickle | `safetensors` for the DAE `state_dict`; `skl2onnx` for the `IsolationForest` companion | **Partial — DAE feasible; IF obstacle** | PyTorch `state_dict` serialisable with `safetensors` (no code, only tensors).  Restoring requires the Python class definition, which must be kept and version-pinned.  `IsolationForest` companion: same obstacle as above. |
| `user_tft.bundle.pkl` | joblib pickle | `safetensors` (state_dict) + JSON (hyper-params, normalisation stats) | **Feasible** | PyTorch only; no sklearn component.  Main effort: wiring `load_state_dict()` through the existing bundle-loading path. |
| `network_gat.bundle.pkl` | joblib pickle | `safetensors` (state_dict) + JSON (graph hyper-params) | **Feasible** | PyTorch only.  Same wiring effort as TFT.  GAT adjacency is derived at inference time, not stored in the bundle. |
| `risk_fusion_meta.joblib` | joblib pickle | Pure JSON (linear coefficients + intercept for `LogisticRegression`; calibration coefficients for `CalibratedClassifierCV`) | **Feasible** | Coefficients are plain floats; a small loader using `numpy` / standard library can reconstruct the predictor without any pickle.  Calibration layer (`sigmoid` / `isotonic`) weights are also float arrays.  Recommended first conversion target. |

### Recommended migration order

1. `risk_fusion_meta.joblib` → JSON (smallest, simplest, no dependencies)
2. `user_tft.bundle.pkl` → `safetensors` + JSON
3. `network_gat.bundle.pkl` → `safetensors` + JSON
4. `endpoint_behavior.bundle.pkl` (DAE part) → `safetensors`; keep IF on
   signed-pickle path until `skl2onnx` is validated
5. `cicids2017_*_lightgbm.bundle.pkl` (booster part) → LightGBM native text;
   IF part requires `skl2onnx` validation

Each migration must include prediction-parity tests comparing the converted
model output to the original bundle output on the CICIDS2017 development set,
with tolerances documented (suggested: absolute difference < 1e-5 for
probability scores).

---

## 6. References

| Document | Contents |
|---|---|
| [`docs/PHASE4_AUDIT.md`](PHASE4_AUDIT.md) | Full file-by-line audit of every load/save path, authentication review, poisoning exposure |
| `backend/ml/models/artifact_security.py` | Manifest builder, SHA-256/HMAC helpers, `verify_and_load_joblib` |
| `backend/ml/models/registry.py` | File-based model registry with signature-verified rollback |
| `backend/ml/models/drift.py` | PSI + KS feature drift and prediction-distribution shift monitoring |
| `scripts/sign_existing_models.py` | One-time CLI to sign bundles already on disk |
| `scripts/model_registry.py` | Registry management CLI (list, activate, rollback) |
| `backend/tests/test_artifact_security.py` | Tampered-file, wrong-key, missing-manifest, truncated-manifest, rollback, unsigned-load flag tests |
| `backend/tests/test_drift_monitoring.py` | PSI/KS drift tests (all data synthetic); endpoint integration tests |
