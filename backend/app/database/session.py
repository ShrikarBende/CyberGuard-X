"""
SQLAlchemy Database setup with session lifecycle management.
"""
from typing import Generator
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import BACKEND_DIR, settings

def resolve_database_url(database_url: str):
    """Resolve relative SQLite database paths from the backend directory."""
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite" and url.database not in (None, "", ":memory:"):
        path = Path(url.database).expanduser()
        if not path.is_absolute():
            path = BACKEND_DIR / path
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        url = url.set(database=str(path))
    return url


database_url = resolve_database_url(settings.DATABASE_URL)
connect_args = {}
if database_url.get_backend_name() == "sqlite":
    connect_args["check_same_thread"] = False

engine = create_engine(
    database_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

