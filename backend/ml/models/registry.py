"""
Model Registry: Tracks paths and operational readiness of ML models.
"""
from pathlib import Path
from typing import Dict, Any
from app.core.config import settings

SAVED_MODELS_DIR = Path(settings.SAVED_MODELS_DIR).resolve()
MODEL_BUNDLE_PATH = Path(settings.MODEL_BUNDLE_PATH)


def get_models_status() -> Dict[str, Any]:
    """Inspect availability of the live real-CICIDS2017 model bundle."""
    bundle_path = MODEL_BUNDLE_PATH
    models = {
        "cicids2017_lightgbm": {
            "name": "CICIDS2017 LightGBM Flow Classifier",
            "file": str(bundle_path),
            "is_trained": bundle_path.is_file(),
            "target": "Known network flow classes (CICIDS2017)",
        }
    }
    all_trained = all(m["is_trained"] for m in models.values())
    return {
        "models": models,
        "all_models_trained": all_trained,
        "saved_models_dir": str(SAVED_MODELS_DIR),
        "model_bundle_path": str(bundle_path),
        "status": "ready" if all_trained else "model_bundle_missing",
    }

