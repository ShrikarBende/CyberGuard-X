"""Focused tests for signed analyst access and the audit trail."""
from __future__ import annotations

from pathlib import Path
import sys

import pytest
import base64
import hashlib
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.api.auth import LoginRequest, login
from app.auth import (
    create_access_token,
    decode_access_token,
    get_current_analyst,
    hash_password,
    password_hash_needs_upgrade,
    require_roles,
    verify_password,
)
from app import auth as auth_module
from app.database.session import Base
from app.models.entities import AnalystAccount, AnalystActivity, Incident
from app.api.endpoints import add_incident_note, update_incident_status
from app.schemas.schemas import InvestigationNoteCreate


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _account(role="analyst", username="casey", password="long-test-password"):
    return AnalystAccount(
        account_id=f"account-{username}", username=username,
        password_hash=hash_password(password), role=role, is_active=True,
    )


def test_passwords_use_unique_salts_and_high_iteration_pbkdf2():
    first = hash_password("test-password")
    second = hash_password("test-password")
    first_parts = first.split("$")
    second_parts = second.split("$")
    assert first_parts[0] == "pbkdf2_sha256"
    assert int(first_parts[1]) == auth_module.settings.PASSWORD_PBKDF2_ITERATIONS == 600_000
    assert first_parts[2] != second_parts[2]
    assert first != second
    assert not verify_password("test-password", "pbkdf2_sha256$1$c2FsdA$ZmFrZWhhc2g=")


def test_legacy_pbkdf2_hash_verifies_and_upgrades_on_login(db):
    password = "legacy-password-123"
    salt = b"legacy-test-salt"
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    legacy_hash = "pbkdf2_sha256$310000${}${}".format(
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    )
    account = _account(password=password)
    account.password_hash = legacy_hash
    db.add(account)
    db.commit()
    assert verify_password(password, legacy_hash)
    assert password_hash_needs_upgrade(legacy_hash)

    result = login(LoginRequest(username="casey", password=password), _request(), db)
    assert result["access_token"]
    assert verify_password(password, account.password_hash)
    assert not password_hash_needs_upgrade(account.password_hash)
    assert account.password_hash != legacy_hash


def _request():
    return Request({
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/api/auth/login",
        "raw_path": b"/api/auth/login", "query_string": b"", "headers": [],
        "server": ("testserver", 80), "client": ("127.0.0.1", 50000),
    })


def test_login_issues_signed_token_and_audits_success_and_failure(db):
    account = _account()
    db.add(account)
    db.commit()

    result = login(LoginRequest(username="CASEY", password="long-test-password"), _request(), db)
    claims = decode_access_token(result["access_token"])
    assert result["analyst"] == {"username": "casey", "role": "analyst"}
    assert claims["sub"] == "casey"
    assert claims["role"] == "analyst"
    assert verify_password("long-test-password", account.password_hash)
    assert not verify_password("wrong", account.password_hash)
    success_audit = db.query(AnalystActivity).filter_by(action_type="login_succeeded").one()
    assert result["access_token"] not in str(success_audit.details)
    assert "long-test-password" not in str(success_audit.details)
    assert auth_module.settings.SECRET_KEY not in str(success_audit.details)

    with pytest.raises(HTTPException) as error:
        login(LoginRequest(username="casey", password="wrong"), _request(), db)
    assert error.value.status_code == 401
    actions = [row.action_type for row in db.query(AnalystActivity).order_by(AnalystActivity.timestamp)]
    assert actions == ["login_succeeded", "login_failed"]


def test_signed_token_is_revalidated_against_active_account_and_role(db):
    account = _account(role="viewer")
    db.add(account)
    db.commit()
    token, _ = create_access_token(account)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    assert get_current_analyst(credentials, db).role == "viewer"
    with pytest.raises(HTTPException) as forbidden:
        require_roles("analyst")(account)
    assert forbidden.value.status_code == 403

    account.is_active = False
    db.commit()
    with pytest.raises(HTTPException) as unauthorized:
        get_current_analyst(credentials, db)
    assert unauthorized.value.status_code == 401


def test_env_bootstrap_creates_only_the_first_account(db, monkeypatch):
    factory = sessionmaker(bind=db.get_bind(), autoflush=False)
    monkeypatch.setattr(auth_module, "SessionLocal", factory)
    monkeypatch.setattr(auth_module.settings, "ADMIN_USERNAME", "first-admin")
    monkeypatch.setattr(auth_module.settings, "ADMIN_PASSWORD", "first-admin-password-123")
    auth_module.ensure_bootstrap_admin()
    with factory() as check_db:
        created = check_db.query(AnalystAccount).all()
        assert len(created) == 1
        assert created[0].username == "first-admin"
        assert created[0].role == "admin"
        assert verify_password("first-admin-password-123", created[0].password_hash)

    monkeypatch.setattr(auth_module.settings, "ADMIN_USERNAME", "second-admin")
    monkeypatch.setattr(auth_module.settings, "ADMIN_PASSWORD", "second-admin-password-123")
    auth_module.ensure_bootstrap_admin()
    with factory() as check_db:
        assert check_db.query(AnalystAccount).count() == 1


def test_tampered_token_is_rejected(db):
    account = _account()
    token, _ = create_access_token(account)
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(ValueError, match="signature"):
        decode_access_token(f"{header}.{payload}.{tampered_signature}")


def test_expired_token_is_rejected(db, monkeypatch):
    account = _account()
    token, _ = create_access_token(account)
    real_datetime = auth_module.datetime

    class FutureDateTime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + __import__("datetime").timedelta(days=1)

    monkeypatch.setattr(auth_module, "datetime", FutureDateTime)
    with pytest.raises(ValueError, match="Expired token"):
        decode_access_token(token)


def test_five_failed_logins_trigger_audited_rate_limit(db):
    auth_module._LOGIN_FAILURES.clear()
    for _ in range(auth_module.LOGIN_FAILURE_LIMIT):
        with pytest.raises(HTTPException) as error:
            login(LoginRequest(username="missing-user", password="bad"), _request(), db)
        assert error.value.status_code == 401
    with pytest.raises(HTTPException) as limited:
        login(LoginRequest(username="missing-user", password="bad"), _request(), db)
    assert limited.value.status_code == 429
    assert db.query(AnalystActivity).filter_by(action_type="login_failed").count() == 5
    assert db.query(AnalystActivity).filter_by(action_type="login_rate_limited").count() == 1
    auth_module._LOGIN_FAILURES.clear()


def test_incident_status_and_note_actions_are_audited(db):
    account = _account()
    db.add(account)
    db.add(Incident(
        incident_id="incident-test", title="Test incident", severity="MEDIUM",
        status="OPEN", threat_classification="test", overall_risk_score=10,
    ))
    db.commit()

    update_incident_status("incident-test", "INVESTIGATING", db, account)
    note = add_incident_note(
        "incident-test", InvestigationNoteCreate(content="Checked endpoint timeline."), db, account,
    )
    rows = db.query(AnalystActivity).order_by(AnalystActivity.action_type).all()
    assert [(row.action_type, row.target_id) for row in rows] == [
        ("note_added", "incident-test"), ("status_changed", "incident-test"),
    ]
    status_row = next(row for row in rows if row.action_type == "status_changed")
    note_row = next(row for row in rows if row.action_type == "note_added")
    assert status_row.details == {"old_status": "OPEN", "new_status": "INVESTIGATING"}
    assert note_row.details["note_id"] == note.note_id
    assert "Checked endpoint timeline." not in str(note_row.details)
    assert note.author == "casey"


def test_websocket_closes_unauthenticated_connections_with_4401():
    from app.api.ws import websocket_live_events_endpoint

    class FakeWebSocket:
        query_params = {}

        def __init__(self):
            self.accepted = False
            self.close_args = None

        async def accept(self):
            self.accepted = True

        async def close(self, code, reason):
            self.close_args = (code, reason)

    websocket = FakeWebSocket()
    coroutine = websocket_live_events_endpoint(websocket)
    with pytest.raises(StopIteration):
        coroutine.send(None)
    assert websocket.accepted
    assert websocket.close_args == (4401, "Valid analyst token required")
