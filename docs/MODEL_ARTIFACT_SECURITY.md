# Model artifact signing and rollback

The application authenticates model files before `joblib` deserialization. The adjacent sidecar is named `<artifact filename>.manifest.json` and contains the artifact SHA-256, model version, optional dataset hash, Git commit, metrics, and an HMAC-SHA-256 signature over the canonical manifest fields. Missing, malformed, mismatched, or unsigned artifacts fail closed. Pickle/joblib remains executable content; only sign bundles from a trusted build or training environment.

## Configure the signing key

Set `MODEL_ARTIFACT_HMAC_KEY` in the deployment secret store or untracked `.env`. Use at least 32 random bytes. Never commit it, print it in build logs, or include it in a manifest. `MODEL_ARTIFACT_HMAC_KEY` must be identical for signing and runtime verification. The application does not fall back to unsigned loading when it is absent.

`FEATURE_DRIFT_PSI_ALERT_THRESHOLD` configures the PSI alert boundary and defaults to `0.2`. Batch inference reports per-feature PSI and two-sample KS statistic/p-value when a model bundle contains a training reference. The checked-in bundles predate this reference, so drift reports appear only after a model is retrained with the updated trainer or an artifact containing `drift_reference` is installed. Single-row inference is not used for KS monitoring.

## Sign and register a trusted artifact

Run from `backend` after setting the key in the environment:

```powershell
python scripts/register_model_artifact.py saved_models/cicids2017_medium_lightgbm.bundle.pkl --name network_flow --version cicids2017-medium-v1
python scripts/register_model_artifact.py saved_models/endpoint_behavior.bundle.pkl --name endpoint --version endpoint-dae-iforest-v1
python scripts/register_model_artifact.py saved_models/user_tft.bundle.pkl --name user_tft --version user-tft-v1
python scripts/register_model_artifact.py saved_models/network_gat.bundle.pkl --name network_gat --version network-gat-v1
python scripts/register_model_artifact.py saved_models/risk_fusion_meta.joblib --name risk_fusion --version risk-fusion-logistic-calibrated-v1
```

The command accepts `--dataset-hash` only when a verified training-data hash is available; otherwise omit it. It signs the source sidecar and stores an immutable, signed version under `backend/saved_models/v/`, then updates `backend/models/registry.json`. The registry records model version, artifact digest, dataset hash, Git commit, and metrics (empty when not supplied). Keep version files and sidecars together.

Training code writes signed manifests when a key is configured. It does not automatically promote every training output to the active registry. Register the resulting trusted artifact before runtime selection. Existing checked-in bundles have no signed manifests by default and therefore cannot load until signed and registered.

## Rollback

From `backend`, select the preceding registry version:

```powershell
python scripts/rollback_model.py network_flow
```

The command changes the registry's active digest and prints the selected artifact path and digest. Restart the application to clear its model cache. The standard loader then verifies the selected version's HMAC and SHA-256 before use. If the prior signed version file or manifest is missing or altered, loading fails closed.

Registry JSON is a version selector, not a trust root: each selected model still must pass HMAC verification. A registry edit can cause denial of service or select another already signed version, but cannot make an unsigned/tampered artifact load.

## Format coverage

All current saved model bundles are composite Python artifacts containing model objects, preprocessors, and branch-specific arrays. Moving them to ONNX, safetensors, or plain JSON is not a trivial export and would need separate parity tests. No alternate export was added in this change.
