"""Alembic adoption and fresh-install coverage using isolated SQLite databases."""
from __future__ import annotations

from pathlib import Path
import sys

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.database.session import Base
from app.main import run_database_migrations
from app.models.entities import User

AGENT_HEAD = "20261125_agent_layer"


def _sqlite_engine(path: Path):
    return create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})


def _revision(engine) -> str:
    with engine.connect() as connection:
        return connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()


def test_fresh_database_is_created_and_upgraded(tmp_path):
    engine = _sqlite_engine(tmp_path / "fresh.db")
    try:
        run_database_migrations(engine)
        assert _revision(engine) == AGENT_HEAD
        assert "analyst_accounts" in inspect(engine).get_table_names()
        assert {"agent_runs", "agent_steps", "action_proposals"}.issubset(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_existing_pre_auth_database_is_stamped_and_upgraded_without_data_loss(tmp_path):
    engine = _sqlite_engine(tmp_path / "legacy.db")
    legacy_tables = [table for table in Base.metadata.sorted_tables
                     if table.name != "analyst_accounts" and table.name != "action_proposals"
                     and not table.name.startswith("agent_")]
    try:
        Base.metadata.create_all(engine, tables=legacy_tables)
        with Session(engine) as db:
            db.add(User(user_id="existing-user", username="preserved"))
            db.commit()

        run_database_migrations(engine)

        assert _revision(engine) == AGENT_HEAD
        assert "analyst_accounts" in inspect(engine).get_table_names()
        assert {"agent_runs", "agent_steps", "action_proposals"}.issubset(inspect(engine).get_table_names())
        with Session(engine) as db:
            preserved = db.get(User, "existing-user")
            assert preserved is not None
            assert preserved.username == "preserved"
    finally:
        engine.dispose()


def test_agent_migration_downgrades_and_reupgrades_on_sqlite(tmp_path):
    engine = _sqlite_engine(tmp_path / "agent-roundtrip.db")
    try:
        run_database_migrations(engine)
        with engine.begin() as connection:
            from alembic.config import Config
            from alembic import command
            config = Config(str(BACKEND_DIR / "alembic.ini"))
            config.attributes["connection"] = connection
            command.downgrade(config, "3e3f12404ef0")
        assert not {"agent_runs", "agent_steps", "action_proposals"}.intersection(inspect(engine).get_table_names())
        with engine.begin() as connection:
            config = Config(str(BACKEND_DIR / "alembic.ini"))
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        assert _revision(engine) == AGENT_HEAD
        assert {"agent_runs", "agent_steps", "action_proposals"}.issubset(inspect(engine).get_table_names())
    finally:
        engine.dispose()
