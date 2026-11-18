"""
Enterprise CyberGuard X - Main FastAPI Application
Entrypoint re-exporting app from app.main.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add backend directory to path if not present
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import (  # noqa: F401
    app,
    lifespan,
    require_analyst_token,
    run_database_migrations,
    unexpected_exception_response,
)

__all__ = [
    "app",
    "lifespan",
    "require_analyst_token",
    "run_database_migrations",
    "unexpected_exception_response",
]
