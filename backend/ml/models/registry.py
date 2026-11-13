"""
Model Registry: Tracks paths and operational readiness of ML models.
"""
import os
from pathlib import Path
from typing import Dict, Any

SAVED_MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "saved_models"
SAVED_MODELS_DIR.mkdir(parents=True, exist_ok=True)


def get_models_status() -> Dict[str, Any]:
    """Inspect availability of trained model weights."""
    models = {
        "isolation_forest": {
            "name": "Isolation Forest (Anomaly Detection)",
            "file": "isolation_forest.pkl",
            "is_trained": (SAVED_MODELS_DIR / "isolation_forest.pkl").exists(),
            "target": "Unsupervised Outlier Scoring"
        },
        "xgboost_classifier": {
            "name": "XGBoost Threat Classifier",
            "file": "xgboost_threats.json",
            "is_trained": (SAVED_MODELS_DIR / "xgboost_threats.json").exists(),
            "target": "Known Threat Classification"
        },
        "denoising_autoencoder": {
            "name": "PyTorch Denoising Autoencoder",
            "file": "autoencoder.pt",
            "is_trained": (SAVED_MODELS_DIR / "autoencoder.pt").exists(),
            "target": "Reconstruction Error Residuals"
        },
        "open_set_centroids": {
            "name": "Open-Set Class Centroids & Covariance",
            "file": "open_set_centroids.pkl",
            "is_trained": (SAVED_MODELS_DIR / "open_set_centroids.pkl").exists(),
            "target": "Mahalanobis Latent Space Distance"
        }
    }
    all_trained = all(m["is_trained"] for m in models.values())
    return {
        "models": models,
        "all_models_trained": all_trained,
        "saved_models_dir": str(SAVED_MODELS_DIR),
        "status": "ready" if all_trained else "partially_trained"
    }

