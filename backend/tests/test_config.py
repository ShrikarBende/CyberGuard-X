from __future__ import annotations

from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import PROJECT_ROOT, Settings


def test_dev_without_secret_generates_temporary_key_and_warns(caplog):
    config = Settings(_env_file=None, APP_ENV="dev", SECRET_KEY="")
    assert config.SECRET_KEY
    assert "Using a temporary dev SECRET_KEY" in caplog.text


def test_unset_app_env_defaults_to_dev(monkeypatch):
    monkeypatch.delenv("APP_ENV", raising=False)
    config = Settings(_env_file=None, SECRET_KEY="")
    assert config.APP_ENV == "dev"
    assert config.SECRET_KEY


def test_production_without_secret_has_fix_hint():
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None, APP_ENV="production", SECRET_KEY="")
    message = str(exc_info.value)
    assert "SECRET_KEY is required" in message
    assert "APP_ENV=dev" in message
    assert "python -c" in message


def test_production_with_secret_starts():
    config = Settings(_env_file=None, APP_ENV="production", SECRET_KEY="test-production-key")
    assert config.APP_ENV == "production"
    assert config.SECRET_KEY == "test-production-key"


def test_each_dev_settings_instance_gets_a_new_temporary_key():
    first = Settings(_env_file=None, APP_ENV="dev", SECRET_KEY="")
    second = Settings(_env_file=None, APP_ENV="dev", SECRET_KEY="")
    assert first.SECRET_KEY
    assert second.SECRET_KEY
    assert first.SECRET_KEY != second.SECRET_KEY


def test_env_file_path_is_project_root_absolute_even_after_chdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = Path(Settings.model_config["env_file"])
    assert env_file.is_absolute()
    assert env_file == PROJECT_ROOT / ".env"
