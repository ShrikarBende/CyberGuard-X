"""
Enterprise CyberGuard X - Application Settings & Configuration
"""
from pathlib import Path
import ipaddress
import logging
import secrets
from typing import List, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent
BASE_DIR = BACKEND_DIR
logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    PROJECT_NAME: str = "Enterprise CyberGuard X"
    APP_ENV: str = "dev"
    DEBUG: bool = True
    SECRET_KEY: str = ""
    ACCESS_TOKEN_MINUTES: int = 60
    PASSWORD_PBKDF2_ITERATIONS: int = Field(
        default=600_000, ge=600_000,
        description="PBKDF2-HMAC-SHA256 iterations for new and upgraded password hashes.",
    )
    ADMIN_USERNAME: str = ""
    ADMIN_PASSWORD: str = ""
    MODEL_BUNDLE_PATH: str = str(
        BASE_DIR / "saved_models" / "cicids2017_medium_lightgbm.bundle.pkl"
    )
    ARTIFACT_HMAC_KEY: str = ""
    ALLOW_UNSIGNED_MODELS: bool = False
    DRIFT_PSI_THRESHOLD: float = 0.25
    DRIFT_KS_THRESHOLD: float = 0.15
    DRIFT_PREDICTION_PSI_THRESHOLD: float = 0.25
    DRIFT_MAX_ROWS: int = Field(default=50_000, ge=1)
    DRIFT_MAX_FEATURES: int = Field(default=500, ge=1)
    # NOT CALIBRATED: placeholder probability gate for rule-based MITRE mapping.
    MITRE_MIN_PROBABILITY: float = 0.7
    RISK_HIGH_THRESHOLD: float = 60.0
    RISK_CRITICAL_THRESHOLD: float = 80.0
    RISK_ANOMALY_WEIGHT: float = 0.5
    RISK_CONFIDENCE_WEIGHT: float = 0.3
    RISK_VERDICT_WEIGHT: float = 0.2
    # NOT CALIBRATED - demo values
    CORRELATION_WINDOW_MINUTES: int = 60
    FAILED_LOGIN_BURST_COUNT: int = 5
    FAILED_LOGIN_BURST_WINDOW_MINUTES: int = 10
    BUSINESS_HOURS_START: int = 8
    BUSINESS_HOURS_END: int = 18
    RARE_OUTBOUND_PORTS: List[int] = [4444, 1337, 31337]
    LARGE_TRANSFER_BYTES: int = 100 * 1024 * 1024
    CORRELATION_MIN_INDICATORS: int = 3
    CORRELATION_MIN_LAYERS: int = 2
    CORRELATION_INDICATOR_WEIGHT: float = 0.6
    CORRELATION_LAYER_WEIGHT: float = 0.4
    MAX_UPLOAD_SIZE_MB: int = 50
    INCIDENT_WINDOW_MINUTES: int = 5

    # The application supports SQLite only.
    DATABASE_URL: str = "sqlite:///./cyberguardx.db"
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    TRUSTED_PROXY_CIDRS: List[str] = Field(default_factory=list)

    LLM_PROVIDER: str = "template_fallback"
    LLM_API_KEY: str = ""
    LLM_API_URL: str = ""
    LLM_MODEL: str = "template"
    AGENT_ENABLED: bool = False
    AGENT_TOOL_MODE: Literal["native", "json"] = "native"
    AGENT_LLM_API_URL: str = ""
    AGENT_LLM_API_KEY: str = ""
    AGENT_LLM_MODEL: str = ""
    AGENT_MAX_STEPS: int = Field(default=6, ge=1, le=12)
    AGENT_MAX_TOOL_CALLS: int = Field(default=12, ge=1, le=30)
    AGENT_WALL_SECONDS: int = Field(default=90, ge=1, le=300)
    AGENT_RESULT_CHARS: int = Field(default=6000, ge=256, le=20000)
    AGENT_MAX_CONCURRENT_RUNS: int = Field(default=2, ge=1, le=4)
    AGENT_MAX_OUTPUT_TOKENS: int = Field(default=1500, ge=1, le=20000)
    AGENT_EXECUTION_MODE: Literal["dry_run"] = "dry_run"
    AGENT_ALLOW_SELF_APPROVAL: bool = False
    AGENT_PROPOSAL_TTL_HOURS: int = Field(default=24, ge=1, le=8760)
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    RAG_TOP_K: int = 4
    RAG_BACKEND: Literal["auto", "numpy", "faiss"] = "auto"
    RAG_MIN_RETRIEVAL_SCORE: float = 0.25
    RAG_CHUNK_WORDS: int = 250
    RAG_CHUNK_OVERLAP_WORDS: int = 40

    RANDOM_SEED: int = 42
    SAVED_MODELS_DIR: str = str(BASE_DIR / "saved_models")
    DATASETS_DIR: str = str(BASE_DIR / "datasets")

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    @field_validator("TRUSTED_PROXY_CIDRS")
    @classmethod
    def validate_trusted_proxy_cidrs(cls, values):
        networks = []
        for value in values:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except (TypeError, ValueError) as exc:
                raise ValueError("TRUSTED_PROXY_CIDRS entries must be valid IP networks") from exc
            if network.prefixlen == 0:
                raise ValueError("TRUSTED_PROXY_CIDRS cannot contain universal trust ranges")
            networks.append(str(network))
        return networks

    @field_validator("MODEL_BUNDLE_PATH", mode="before")
    @classmethod
    def resolve_model_bundle_path(cls, value):
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = BACKEND_DIR / path
        return str(path.resolve())

    @model_validator(mode="after")
    def require_secret_outside_dev(self):
        if not self.SECRET_KEY or not self.SECRET_KEY.strip():
            if self.APP_ENV == "dev":
                self.SECRET_KEY = secrets.token_hex(32)
                logger.warning("Using a temporary dev SECRET_KEY")
            else:
                raise ValueError(
                    "SECRET_KEY is required when APP_ENV is not 'dev'. Set APP_ENV=dev for local "
                    "development, or set a strong SECRET_KEY in the project-root .env or environment "
                    "(generate one with: python -c \"import secrets; print(secrets.token_hex(32))\")."
                )
        return self

    @model_validator(mode="after")
    def agent_llm_defaults(self):
        self.AGENT_LLM_API_URL = self.AGENT_LLM_API_URL or self.LLM_API_URL
        self.AGENT_LLM_API_KEY = self.AGENT_LLM_API_KEY or self.LLM_API_KEY
        self.AGENT_LLM_MODEL = self.AGENT_LLM_MODEL or self.LLM_MODEL
        return self


settings = Settings()

