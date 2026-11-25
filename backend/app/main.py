"""
Enterprise CyberGuard X - Main FastAPI Application
"""
import sys
import importlib.util
import json
from pathlib import Path
from contextlib import asynccontextmanager

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.core.config import settings
from app.api.endpoints import router as api_router
from app.api.auth import router as auth_router
from app.api.ws import router as ws_router
from app.agent.api import router as agent_router
from app.database.session import engine, SessionLocal, get_db
from app.auth import account_for_token, get_current_analyst
import joblib
from alembic import command
from alembic.config import Config
from app.database.session import Base
from app.models import entities as _entities  # noqa: F401
import logging

LEGACY_BASELINE_REVISION = "73715c0b6c8b"
logger = logging.getLogger(__name__)


def _baseline_schema_matches(connection) -> bool:
    from sqlalchemy import inspect

    baseline_tables = {
        name: {column.name for column in table.columns}
        for name, table in Base.metadata.tables.items()
        if name != "analyst_accounts" and name != "action_proposals" and not name.startswith("agent_")
    }
    inspector = inspect(connection)
    existing_tables = set(inspector.get_table_names()) - {"alembic_version"}
    if existing_tables != set(baseline_tables):
        return False
    return all(
        {column["name"] for column in inspector.get_columns(table_name)} == columns
        for table_name, columns in baseline_tables.items()
    )


def run_database_migrations(database_engine=engine) -> None:
    """Upgrade a new DB or safely adopt only an exact pre-auth baseline schema."""
    from sqlalchemy import inspect

    config = Config(str(backend_dir / "alembic.ini"))
    with database_engine.connect() as connection:
        config.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())
        legacy_tables = tables - {"alembic_version"}
        if legacy_tables and "alembic_version" not in tables:
            if not _baseline_schema_matches(connection):
                raise RuntimeError(
                    "Existing database schema does not match the Alembic baseline, so startup "
                    "stopped without changing data. Back up first (copy the SQLite file or use "
                    "pg_dump), compare its tables and columns with the baseline revision, then "
                    "apply a reviewed migration before restarting. Do not drop or recreate the database."
                )
            command.stamp(config, LEGACY_BASELINE_REVISION)
            logger.info("Existing schema matched Alembic baseline; stamped revision %s", LEGACY_BASELINE_REVISION)
            # SQLite DDL is not transactional. Persist the stamp before applying
            # the follow-on migration so a restart never reapplies the baseline.
            connection.commit()
        command.upgrade(config, "head")
        connection.commit()


def _print_startup_summary() -> None:
    model_path = Path(settings.MODEL_BUNDLE_PATH)
    if not model_path.is_file():
        raise RuntimeError(
            f"Configured CICIDS model bundle was not found: {model_path}. "
            "Set MODEL_BUNDLE_PATH to an existing bundle; no alternate bundle is loaded."
        )
    try:
        bundle = joblib.load(model_path)
    except Exception as exc:
        raise RuntimeError(f"Could not read configured CICIDS model bundle: {model_path}: {exc}") from exc
    profile = bundle.get("profile", {})
    profile_name = profile.get("name") if isinstance(profile, dict) else profile
    evaluation_config = bundle.get("evaluation_config", {})
    sample_fraction = (profile.get("sample_fraction") if isinstance(profile, dict) else None)
    if sample_fraction is None:
        sample_fraction = evaluation_config.get("sample_fraction", bundle.get("sample_fraction", "unknown"))
    model_metadata = (
        f"model_version={bundle.get('model_version', 'unknown')} "
        f"profile={profile_name or evaluation_config.get('profile', 'unknown')} "
        f"sample_fraction={sample_fraction} tau={bundle.get('tau', 'unknown')} "
        f"evaluation_json_path={bundle.get('evaluation_json_path', 'unknown')}"
    )

    rag_index_dir = backend_dir / "app" / "rag" / "index"
    metadata_path = rag_index_dir / "metadata.json"
    index_exists = metadata_path.is_file() and (
        (rag_index_dir / "knowledge.faiss").is_file()
        or (rag_index_dir / "vectors.npy").is_file()
    )
    faiss_backend = None
    if index_exists:
        try:
            faiss_backend = json.loads(metadata_path.read_text(encoding="utf-8")).get("backend")
        except (OSError, json.JSONDecodeError):
            faiss_backend = None
    if not faiss_backend:
        faiss_backend = (
            "faiss (available; index will build on first retrieval)"
            if importlib.util.find_spec("faiss")
            else "numpy fallback (FAISS unavailable; index will build on first retrieval)"
        )

    database_url = engine.url.render_as_string(hide_password=True)
    database_path = engine.url.database if engine.url.get_backend_name() == "sqlite" else "(not SQLite)"
    print(
        "Startup configuration: "
        f"APP_ENV={settings.APP_ENV}; "
        f"DATABASE_URL={database_url}; DATABASE_PATH={database_path}; "
        f"CICIDS_model_bundle=found path={model_path} {model_metadata}; "
        f"RAG_index={'exists' if index_exists else 'not found'} path={rag_index_dir}; "
        f"FAISS_backend={faiss_backend}",
        flush=True,
    )


@asynccontextmanager
async def lifespan(_app):
    run_database_migrations()
    from app.auth import ensure_bootstrap_admin
    ensure_bootstrap_admin()
    _print_startup_summary()
    yield

app = FastAPI(
    title="Enterprise CyberGuard X",
    description="AI-Powered Enterprise Cybersecurity Threat Detection, Investigation and Monitoring Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(_request: Request, exc: RequestValidationError):
    """Avoid reflecting request values such as passwords or bearer tokens in errors."""
    safe_errors = []
    for error in exc.errors():
        safe_errors.append({key: error[key] for key in ("type", "loc", "msg", "url") if key in error})
    return JSONResponse(status_code=422, content={"detail": safe_errors})


@app.exception_handler(Exception)
def unexpected_exception_response(_request: Request, exc: Exception):
    """Return diagnostic exception details only in development mode."""
    logger.error("Unhandled API exception type=%s", type(exc).__name__)
    detail = (
        f"{type(exc).__name__}: {exc}"
        if settings.APP_ENV == "dev"
        else "Internal server error."
    )
    return JSONResponse(status_code=500, content={"detail": detail})


@app.middleware("http")
async def require_analyst_token(request: Request, call_next):
    """Require a bearer token except for preflight, login, and health requests."""
    public_routes = {
        ("POST", "/api/auth/login"),
        ("GET", "/api/health"),
    }
    if request.method == "OPTIONS" or (request.method, request.url.path) in public_routes:
        return await call_next(request)

    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return JSONResponse(
            status_code=401,
            content={"detail": "A valid analyst bearer token is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        override = request.app.dependency_overrides.get(get_db)
        if override is None:
            with SessionLocal() as db:
                account = account_for_token(token.strip(), db)
        else:
            session_generator = override()
            try:
                db = next(session_generator)
                account = account_for_token(token.strip(), db)
            finally:
                session_generator.close()
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeError):
        account = None
    if account is None:
        return JSONResponse(
            status_code=401,
            content={"detail": "A valid analyst bearer token is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.analyst = account
    return await call_next(request)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(ws_router)
app.include_router(agent_router)


@app.get("/", dependencies=[Depends(get_current_analyst)])
def root():
    return {
        "platform": "Enterprise CyberGuard X",
        "status": "operational",
        "version": "2.0.0",
        "docs": "/docs",
        "api": "/api",
        "websocket": "/ws/live-events"
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "CyberGuard X Backend",
        "database": "connected"
    }

