"""
Enterprise CyberGuard X - Application Settings & Configuration
"""
from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    PROJECT_NAME: str = "Enterprise CyberGuard X"
    APP_ENV: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "cyberguardx-production-grade-secret-key-32charsmin!"

    DATABASE_URL: str = "sqlite:///./cyberguardx.db"
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    LLM_PROVIDER: str = "template_fallback"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "template"
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    RANDOM_SEED: int = 42
    SAVED_MODELS_DIR: str = str(BASE_DIR / "saved_models")
    DATASETS_DIR: str = str(BASE_DIR / "datasets")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

