# Phase 4 Step 0 — Model Artifact Security and Lifecycle Audit

Status: **read-only audit** (no code, configuration, or model changes). Line numbers refer to the working tree on `phase-4-model-security`.

---

## 1. Model, Bundle, Calibrator, and Scaler Save/Load Sites

Every runtime and training serialization call found in `backend/`:

### Runtime / Inference Load Sites
| Component | File & Line | Format | Path Source |
|---|---|---|---|
| Startup summary (Network LightGBM) | `backend/app/main.py:90` | `joblib.load` (pickle) | `settings.MODEL_BUNDLE_PATH` (`backend/app/core/config.py:30-32`, env-configurable, default `backend/saved_models/cicids2017_medium_lightgbm.bundle.pkl`) |
| Live network classifier + scaler + open-set calibrators | `backend/app/detection/engine.py:357` | `joblib.load` (pickle) | `MODEL_BUNDLE_PATH = Path(settings.MODEL_BUNDLE_PATH)` (`engine.py:42`) |
| Endpoint DAE + IsolationForest + bounds | `backend/app/detection/engine.py:159` | `joblib.load` (pickle) | Hardcoded filename `endpoint_behavior.bundle.pkl` under `settings.SAVED_MODELS_DIR` (`engine.py:45-48`) |
| User sequence TFT + min/range bounds | `backend/app/detection/engine.py:173` | `joblib.load` (pickle) | Hardcoded filename `user_tft.bundle.pkl` under `settings.SAVED_MODELS_DIR` (`engine.py:45-50`) |
| Host-graph GAT + node/edge state | `backend/app/detection/engine.py:186` | `joblib.load` (pickle) | Hardcoded filename `network_gat.bundle.pkl` under `settings.SAVED_MODELS_DIR` (`engine.py:45-51`) |
| Risk fusion LogisticRegression + StandardScaler | `backend/ml/fusion_meta.py:57` | `joblib.load` (pickle) | Optional `path` parameter (internal callers pass `None`), defaulting to `ARTIFACT_PATH` (`backend/saved_models/risk_fusion_meta.joblib`, `fusion_meta.py:20,52`) |
| Retrain pre-read (existing network bundle) | `backend/app/api/endpoints.py:824` | `joblib.load` (pickle) | `ARTIFACT_PATH` or `MEDIUM_ARTIFACT_PATH` selected by `request.profile` (`"light"` vs `"medium"`, `endpoints.py:789`) |
| Retrain verification read (staged network bundle) | `backend/app/api/endpoints.py:846` | `joblib.load` (pickle) | `temporary` path in same dir as `target` (`endpoints.py:791`) |
| Retrain pre-read (existing fusion bundle) | `backend/app/api/endpoints.py:859` | `joblib.load` (pickle) | Hardcoded `ml.fusion_meta.ARTIFACT_PATH` (`endpoints.py:854`) |
| Retrain verification read (staged fusion bundle) | `backend/app/api/endpoints.py:865` | `joblib.load` (pickle) | `fusion_temporary` in same dir as `FUSION_ARTIFACT_PATH` (`endpoints.py:856`) |
| Replay summary helper | `backend/ml/training/replay_summary.py:88` | `joblib.load` (pickle) | Imported `ARTIFACT_PATH` from `train_final` (CLI/offline script) |

*(Note: RAG vector/FAISS index files in `backend/app/rag/indexer.py:213,217,259,269` use `np.load`/`np.save` and `faiss.read_index`/`faiss.write_index` for text chunk embeddings, not ML model bundles.)*

### Training / Offline Save Sites
| Component | File & Line | Format | Path Source |
|---|---|---|---|
| Network LightGBM + scaler + PCA + IsolationForest + open-set calibrators | `backend/ml/training/train_final.py:246` | `joblib.dump(..., compress=3)` | `output_path` arg or `ARTIFACT_PATH` / `MEDIUM_ARTIFACT_PATH` (`saved_models/cicids2017[_medium]_lightgbm.bundle.pkl`) |
| Endpoint DAE + IsolationForest + bounds | `backend/ml/training/train_endpoint_branch.py:129` | `joblib.dump(..., compress=3)` | `output_path` arg or `ARTIFACT_PATH` (`saved_models/endpoint_behavior.bundle.pkl`) |
| User sequence TFT + quantiles | `backend/ml/training/train_user_tft.py:168` | `joblib.dump(..., compress=3)` | `output_path` arg or `ARTIFACT_PATH` (`saved_models/user_tft.bundle.pkl`) |
| Network graph GAT + graph cache | `backend/ml/training/train_network_gat.py:106` | `joblib.dump(..., compress=3)` | `output_path` arg or `ARTIFACT_PATH` (`saved_models/network_gat.bundle.pkl`) |
| Risk fusion LogisticRegression + StandardScaler | `backend/ml/training/train_fusion_meta.py:151` | `joblib.dump(..., compress=3)` | `output_path` arg or `ARTIFACT_PATH` (`saved_models/risk_fusion_meta.joblib`) |

---

## 2. User / Upload / API Influence on Load Paths

- **Upload endpoints (`/api/upload`, `/api/analyze`):** No upload endpoint accepts or loads model files; uploads are parsed strictly as CSV/JSON telemetry events (`backend/app/ingestion/parser.py`).
- **API request parameters:**
  - `POST /api/models/retrain` (`backend/app/api/endpoints.py:778-789`) accepts `RetrainRequest.profile`, which is restricted to `"light"` or `"medium"` and maps to one of two fixed constants (`ARTIFACT_PATH` or `MEDIUM_ARTIFACT_PATH`). No arbitrary path or filename is accepted from the caller.
  - `load_fusion_bundle(path=...)` (`backend/ml/fusion_meta.py:50`) accepts a `path` argument in Python, but no API route exposes it; runtime callers pass no argument.
- **Process/environment config:** `settings.MODEL_BUNDLE_PATH` and `settings.SAVED_MODELS_DIR` come from `.env` / environment variables (`backend/app/core/config.py:30,90`).
- **Residual risk:** While a remote API user cannot supply a path, **any local file tampering** in `backend/saved_models/` (6 files totaling ~16.8 MB: `cicids2017_lightgbm.bundle.pkl`, `cicids2017_medium_lightgbm.bundle.pkl`, `endpoint_behavior.bundle.pkl`, `user_tft.bundle.pkl`, `network_gat.bundle.pkl`, `risk_fusion_meta.joblib`) will result in arbitrary code execution upon `joblib.load()`, because **no cryptographic hash or HMAC signature is checked before deserialization**.

---

## 3. Safe-Format Feasibility by Model Type

| Model / Component | Current Objects in Bundle | Safe Format Feasible? | What Would Be Lost / Caveats |
|---|---|---|---|
| **Network classifier** (`LGBMClassifier`) | `model` (`LGBMClassifier`), `feature_names`, `class_names`, `tau` | **Partially / Yes (LightGBM native text/JSON or ONNX)** | LightGBM's `booster_.save_model()` / `model_to_string()` is plain text/JSON (zero pickle). Converting to ONNX (`onnxmltools`) requires extra dependency and float32/64 parity verification. **However**, the surrounding bundle also embeds sklearn objects (`StandardScaler`, `PCA`, `IsolationForest` — see below). |
| **Network preprocessors & open-set calibrators** (`StandardScaler`, `compact_scaler`, `compact_pca`, `IsolationForest`, centroids, quantiles) | `scaler`, `compact_scaler`, `compact_pca`, `open_set_isolation_forest`, `class_centroids`, `centroid_covariance`, `open_set_component_references`, scalar thresholds | **Mostly Yes (JSON + safetensors/npz)**, **No for `IsolationForest`** | `StandardScaler` (`mean_`, `scale_`), `PCA` (`components_`, `mean_`), `class_centroids`, `centroid_covariance`, `log1p_columns`, and scalar thresholds/quantiles can all be stored cleanly in JSON + `safetensors` (or `np.load(..., allow_pickle=False)`). **`IsolationForest`** is a scikit-learn ensemble of `ExtraTreeRegressor` objects without a trivial zero-dependency JSON format (unless exported to ONNX via `skl2onnx` — **UNVERIFIED** whether `skl2onnx`/`onnxmltools` are installed or match `score_samples` within tolerance). |
| **Endpoint DAE + IsolationForest** | PyTorch `nn.Module` (`dae`), sklearn `IsolationForest`, `feature_min`, `feature_range`, bounds | **PyTorch DAE: Yes (`safetensors`); IsolationForest: No (without ONNX)** | Saving `dae.state_dict()` in `safetensors` + normalization bounds in JSON is straightforward and requires instantiating the `nn.Module` class in code before `load_state_dict()`. `IsolationForest` still requires verified pickle or ONNX (`skl2onnx` **UNVERIFIED**). |
| **User sequence TFT** | PyTorch `nn.Module` (`model`), `feature_names`, `feature_min`, `feature_range`, `sequence_length`, `train_score_quantiles` | **Yes (`safetensors` + JSON)** | Entire bundle can be saved as `safetensors` (`model.state_dict()`) + JSON metadata/bounds/quantiles. Requires instantiating the TFT architecture from `ml/sequence_graph.py` at load time. |
| **Host-graph GAT** | PyTorch `nn.Module` (`model`), `host_index`, `node_features_by_host` (ndarrays), `incoming_by_host`, `top_training_edges` | **Yes (`safetensors` + JSON)** | `model.state_dict()` and `node_features_by_host` tensors fit cleanly in `safetensors`; `host_index`, `incoming_by_host`, and `top_training_edges` fit in JSON. |
| **Risk fusion meta-classifier** | `StandardScaler`, `CalibratedClassifierCV` / `LogisticRegression`, `positive_coefficients`, thresholds, metrics | **Yes (JSON)** | For linear `LogisticRegression` + `StandardScaler` + Platt/sigmoid calibration (`CalibratedClassifierCV` with `sigmoid`), weights (`coef_`, `intercept_`, calibrator slope/intercept `a_`, `b_`, scaler `mean_`, `scale_`) can be serialized in pure JSON and evaluated directly with `numpy`, or kept as verified-pickle if `CalibratedClassifierCV` folds are preserved verbatim. |

*Package availability note:* Whether `safetensors`, `onnxmltools`, or `skl2onnx` are installed in the current Python environment is **UNVERIFIED** (no import test was run in this read-only audit).

---

## 4. What Retrain Endpoint and Background Jobs Write (and Where)

1. **`POST /api/models/retrain`** (`backend/app/api/endpoints.py:778-909`):
   - Runs a background `threading.Thread` (`retrain-<profile>-<job_id[:8]>`).
   - **Writes network bundle:** Stages a temporary file `.<target.name>.<job_id>.tmp` in `backend/saved_models/`, runs `train_final(profile=..., output_path=temporary, ...)`, reloads it via `joblib.load(trained_path)` to check `model_version`, then atomically replaces `target` (`cicids2017_lightgbm.bundle.pkl` or `cicids2017_medium_lightgbm.bundle.pkl`) via `os.replace(trained_path, target)`.
   - **Conditionally writes fusion bundle:** If any `analyst_feedback` records in SQLite contain `fusion_features`, stages `.<FUSION_ARTIFACT_PATH.name>.<job_id>.tmp`, runs `train_fusion_meta(...)`, reloads via `joblib.load`, and atomically replaces `backend/saved_models/risk_fusion_meta.joblib` (`endpoints.py:853-868`).
   - **Updates in-memory state:** Updates `_RETRAIN_JOBS[job_id]` (in-process dict), refreshes `detection_engine._MODEL_BUNDLE_CACHE` if `target` matches `MODEL_BUNDLE_PATH`, and writes an `AnalystActivity` row (`action_type="model_retrained"`) with `before_after` metrics to SQLite (`endpoints.py:872-895`).
   - **Cleans up:** Deletes `temporary` on failure.
2. **Other background jobs in `endpoints.py`:**
   - Upload background processing (`endpoints.py:931-1060`) and evaluation job threads (`endpoints.py:1065-1107`) write to SQLite / evaluation result JSONs, not model bundles.

---

## 5. Existing Drift and Version Information

- **Version metadata:**
  - Every bundle stores a `model_version` string (e.g., `cicids2017-...`, `endpoint-dae-iforest-v1`, `user-tft-v1`, `network-gat-v1`, `fusion_meta_v1` — exact saved values in `backend/saved_models/*.pkl` not deserialized in this read-only audit, **UNVERIFIED**).
  - Network bundle also stores `data_hash`, `seed`, `training_date`, `evaluation_json_path`, `profile`, `split_type`, `training_parameters`, and `feedback_adaptation`.
  - `backend/ml/models/registry.py:12-30` (`get_models_status()`) checks only `MODEL_BUNDLE_PATH.is_file()` and returns file path + boolean `is_trained`; it does **not** track version history, SHA-256 checksums, metrics, or support rollback.
- **Drift monitoring:**
  - **None exists.** A search across `backend/` for `drift`, `psi`, or `kolmogorov` returned zero matches. There is currently no feature-distribution drift check (PSI/KS) and no prediction-distribution shift monitor.

---

## 6. Retrain Auth, Analyst Feedback Poisoning Exposure, and Saved-Models Writers (Step 1 Pre-Check)

- **Authentication, role, and rate limiting on `POST /api/models/retrain`:**
  - Requires an authenticated `AnalystAccount` with role `"admin"` (`Depends(require_roles("admin"))` at `backend/app/api/endpoints.py:781`).
  - **Not rate-limited** by an HTTP rate limiter; concurrency is guarded only by `_RETRAIN_JOBS_LOCK` (`endpoints.py:792-794`), which returns `409 Conflict` while a retrain job is `"running"`.
- **Who can write `analyst_feedback` rows and fusion-retrain influence:**
  - Any `"analyst"` or `"admin"` account (`Depends(require_roles("analyst", "admin"))`) can trigger `analyst_feedback` writes via `PATCH /api/incidents/{incident_id}/status` with `status` in `{"CONFIRMED", "FALSE_POSITIVE"}` (`endpoints.py:475-499`) or `POST /api/incidents/{incident_id}/notes` with `note_in.feedback_label` set (`endpoints.py:556-585`).
  - During `POST /api/models/retrain`, all `AnalystActivity` rows with `action_type == "analyst_feedback"` (`endpoints.py:809-812`) that have `fusion_features` (`endpoints.py:851`) are passed to `train_fusion_meta(..., feedback_samples=fusion_feedback)` (`endpoints.py:864`), which appends each valid sample to `x_train`/`y_train` (`backend/ml/training/train_fusion_meta.py:96-105`).
  - **Data-poisoning exposure:** Because there is no per-incident deduplication, per-analyst cap, or feedback-weight cap, a compromised `"analyst"` account can repeatedly submit `CONFIRMED`/`FALSE_POSITIVE` labels on the same incident(s) to oversample/skew `x_train` when an `"admin"` triggers retraining.
  - **What limits it today:** (1) `"viewer"` accounts cannot write feedback; (2) `fusion_features` are constructed server-side from persisted `Incident`/`DetectionResult` records (`_incident_feedback_sample`, `endpoints.py:504-533`) rather than arbitrary client-supplied feature vectors; (3) `train_fusion_meta` validates finite vectors and `target in (0, 1)` (`train_fusion_meta.py:99-102`); (4) retraining itself requires `"admin"` (`endpoints.py:781`).
- **Other writers to `backend/saved_models/`:**
  - None in application or script code outside `POST /api/models/retrain` (`endpoints.py:850,866`) and the five training scripts (`train_final.py:246`, `train_endpoint_branch.py:129`, `train_user_tft.py:168`, `train_network_gat.py:106`, `train_fusion_meta.py:151`).

