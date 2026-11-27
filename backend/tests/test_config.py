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


def test_trusted_proxy_cidrs_default_empty_and_accept_ipv4_ipv6(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_CIDRS", raising=False)
    config = Settings(_env_file=None, SECRET_KEY="test-key")
    assert config.TRUSTED_PROXY_CIDRS == []
    configured = Settings(
        _env_file=None,
        SECRET_KEY="test-key",
        TRUSTED_PROXY_CIDRS=["192.0.2.10/32", "2001:db8::10/128"],
    )
    assert configured.TRUSTED_PROXY_CIDRS == ["192.0.2.10/32", "2001:db8::10/128"]


@pytest.mark.parametrize("cidr", ["not-a-cidr", "0.0.0.0/0", "::/0"])
def test_trusted_proxy_cidrs_reject_invalid_and_universal_ranges(cidr):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, SECRET_KEY="test-key", TRUSTED_PROXY_CIDRS=[cidr])


def test_trusted_proxy_cidrs_json_environment_value(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", '["192.0.2.10/32", "2001:db8::10/128"]')
    config = Settings(_env_file=None, SECRET_KEY="test-key")
    assert config.TRUSTED_PROXY_CIDRS == ["192.0.2.10/32", "2001:db8::10/128"]


def test_trusted_proxy_validation_error_hides_input_value():
    sentinel = "secret-value-must-not-leak"
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None, SECRET_KEY=sentinel, TRUSTED_PROXY_CIDRS=["invalid-cidr"])
    assert sentinel not in str(exc_info.value)
