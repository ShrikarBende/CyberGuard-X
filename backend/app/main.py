"""
Enterprise CyberGuard X - Main FastAPI Application
"""
import sys
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.endpoints import router as api_router
from app.api.ws import router as ws_router
from app.database.session import engine, Base

# Ensure all database tables exist
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Enterprise CyberGuard X",
    description="AI-Powered Enterprise Cybersecurity Threat Detection, Investigation and Monitoring Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

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
app.include_router(ws_router)


@app.get("/")
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

