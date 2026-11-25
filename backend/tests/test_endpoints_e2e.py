"""API authorization smoke tests through httpx ASGITransport (Windows safe)."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

backend_dir = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(backend_dir))

from app.main import app
from app.auth import create_access_token, hash_password
from app.auth import _b64url, _unb64url
from app.core.config import settings
from app.database.session import Base, get_db
from app.models.entities import AnalystAccount

pytestmark = pytest.mark.requires_linux(
    reason="Windows Python 3.13 hangs initializing its asyncio socketpair; run this ASGITransport suite on Linux."
)


@pytest_asyncio.fixture
async def api_clients(tmp_path):
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'api.db'}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(test_engine)
    TestSession = sessionmaker(autoflush=False, bind=test_engine)
    tokens = {}
    with TestSession() as db:
        for username, role in (("test-admin", "admin"), ("test-analyst", "analyst"), ("test-viewer", "viewer")):
            account = AnalystAccount(
                account_id=f"account-{username}", username=username,
                password_hash=hash_password("api-test-password-123"), role=role, is_active=True,
            )
            db.add(account)
            db.flush()
            tokens[role], _ = create_access_token(account)
        db.commit()

    def override_get_db():
        with TestSession() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
            headers={"Authorization": f"Bearer {tokens['admin']}"},
        ) as admin_client:
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as anonymous_client:
                yield admin_client, anonymous_client, tokens
    finally:
        app.dependency_overrides.pop(get_db, None)
        test_engine.dispose()


def _http_routes():
    for route in app.routes:
        if not hasattr(route, "methods") or not hasattr(route, "path"):
            continue
        for method in (route.methods or set()) & {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            yield method, route.path


def _concrete_path(path: str) -> str:
    return re.sub(r"\{[^}/]+\}", "test-id", path)


@pytest.mark.asyncio
async def test_health_is_public_and_every_other_http_route_requires_a_token(api_clients):
    _, anonymous, _ = api_clients
    assert (await anonymous.get("/api/health")).status_code == 200
    seen = set()
    for method, route_path in _http_routes():
        if (method, route_path) == ("POST", "/api/auth/login"):
            continue
        if (method, route_path) == ("GET", "/api/health"):
            continue
        key = (method, route_path)
        if key in seen:
            continue
        seen.add(key)
        response = await anonymous.request(method, _concrete_path(route_path))
        assert response.status_code == 401, f"{method} {route_path} returned {response.status_code}"


@pytest.mark.asyncio
async def test_viewer_gets_forbidden_for_every_write_route(api_clients, monkeypatch):
    _, anonymous, tokens = api_clients
    # Exercise role authorization even when CI has the opt-in agent setting disabled.
    monkeypatch.setattr(settings, "AGENT_ENABLED", True)
    cases = {
        ("POST", "/api/auth/users"): {"json": {"username": "other", "password": "new-password-123", "role": "viewer"}},
        ("POST", "/api/demo/load"): {},
        ("DELETE", "/api/demo/events"): {},
        ("POST", "/api/demo/replay"): {"json": {"n": 1, "speed": 0}},
        ("POST", "/api/demo/replay/stop"): {},
        ("POST", "/api/correlation/run"): {},
        ("PATCH", "/api/incidents/{incident_id}/status"): {"params": {"status": "INVESTIGATING"}},
        ("POST", "/api/incidents/{incident_id}/notes"): {"json": {"content": "test note"}},
        ("POST", "/api/incidents/{incident_id}/investigate"): {},
        ("POST", "/api/incidents/{incident_id}/agent-investigate"): {},
        ("POST", "/api/agent/runs/{run_id}/cancel"): {},
        ("POST", "/api/agent/proposals/{proposal_id}/approve"): {"json": {"note": "test"}},
        ("POST", "/api/agent/proposals/{proposal_id}/reject"): {"json": {"note": "test"}},
        ("POST", "/api/rag/chat"): {"json": {"query": "test"}},
        ("POST", "/api/models/retrain"): {"json": {"profile": "light"}},
        ("POST", "/api/upload"): {"files": {"file": ("empty.json", "[]", "application/json")}},
        ("POST", "/api/analyze"): {"json": {"event_type": "test", "event_category": "auth"}},
        ("POST", "/api/evaluation/run"): {},
    }
    discovered_writes = {
        (method, path) for method, path in _http_routes()
        if method in {"POST", "PUT", "PATCH", "DELETE"}
        and (method, path) != ("POST", "/api/auth/login")
    }
    assert set(cases) == discovered_writes
    for (method, route_path), kwargs in cases.items():
        response = await anonymous.request(
            method, _concrete_path(route_path),
            headers={"Authorization": f"Bearer {tokens['viewer']}"}, **kwargs,
        )
        assert response.status_code == 403, f"{method} {route_path} returned {response.status_code}"


@pytest.mark.asyncio
async def test_analyst_is_forbidden_from_admin_operations(api_clients):
    _, anonymous, tokens = api_clients
    admin_routes = [
        ("POST", "/api/auth/users", {"json": {"username": "other", "password": "new-password-123", "role": "viewer"}}),
        ("POST", "/api/demo/load", {}),
        ("DELETE", "/api/demo/events", {}),
        ("POST", "/api/demo/replay", {"json": {"n": 1, "speed": 0}}),
        ("POST", "/api/demo/replay/stop", {}),
        ("POST", "/api/correlation/run", {}),
        ("POST", "/api/models/retrain", {"json": {"profile": "light"}}),
        ("POST", "/api/evaluation/run", {}),
    ]
    for method, path, kwargs in admin_routes:
        response = await anonymous.request(
            method, path,
            headers={"Authorization": f"Bearer {tokens['analyst']}"}, **kwargs,
        )
        assert response.status_code == 403, f"{method} {path} returned {response.status_code}"


@pytest.mark.asyncio
async def test_tampered_and_expired_tokens_are_unauthorized(api_clients):
    _, anonymous, tokens = api_clients
    parts = tokens["analyst"].split(".")
    parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    valid_parts = tokens["analyst"].split(".")
    claims = json.loads(_unb64url(valid_parts[1]))
    claims["exp"] = 1
    signing_input = f"{valid_parts[0]}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = hmac.new(settings.SECRET_KEY.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    expired_token = f"{signing_input}.{_b64url(signature)}"
    for token in (".".join(parts), expired_token):
        response = await anonymous.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert token not in response.text


@pytest.mark.asyncio
async def test_validation_errors_do_not_echo_password_values(api_clients):
    _, anonymous, _ = api_clients
    password = "x" * 160
    response = await anonymous.post(
        "/api/auth/login", json={"username": "test-viewer", "password": password}
    )
    assert response.status_code == 422
    assert password not in response.text


@pytest.mark.asyncio
async def test_failed_login_is_audited_and_rate_limited(api_clients):
    _, anonymous, _ = api_clients
    for attempt in range(5):
        response = await anonymous.post("/api/auth/login", json={"username": "missing", "password": "bad"})
        assert response.status_code == 401, f"failed login {attempt + 1} returned {response.status_code}"
    limited = await anonymous.post("/api/auth/login", json={"username": "missing", "password": "bad"})
    assert limited.status_code == 429
