"""Windows-safe route authorization metadata audit; no ASGI/event loop required."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.routing import APIRoute

BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.auth import get_current_analyst
from app.main import app, require_analyst_token


def _walk_dependencies(dependant):
    yield dependant
    for child in dependant.dependencies:
        yield from _walk_dependencies(child)


def _route_auth_metadata(route):
    tree = list(_walk_dependencies(route.dependant))
    has_auth = any(node.call is get_current_analyst for node in tree)
    role_sets = [node.call.required_roles for node in tree if hasattr(node.call, "required_roles")]
    required_roles = set.intersection(*(set(roles) for roles in role_sets)) if role_sets else None
    if required_roles:
        rank = {"viewer": 0, "analyst": 1, "admin": 2}
        minimum_role = min(required_roles, key=rank.__getitem__)
    else:
        minimum_role = "viewer" if has_auth else "public"
    return has_auth, role_sets, minimum_role


def test_every_http_route_declares_auth_and_writes_require_minimum_role():
    http_routes = [route for route in app.routes if getattr(route, "methods", None)]
    routes = [route for route in http_routes if isinstance(route, APIRoute)]
    assert routes, "Expected FastAPI HTTP routes to audit"
    internal_docs_routes = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    middleware_guards_http = any(
        item.kwargs.get("dispatch") is require_analyst_token for item in app.user_middleware
    )
    assert middleware_guards_http
    public = {("POST", "/api/auth/login"), ("GET", "/api/health")}
    admin_only = {
        ("POST", "/api/auth/users"),
        ("POST", "/api/models/retrain"),
        ("POST", "/api/evaluation/run"),
    }
    assert next(
        _route_auth_metadata(route)[2]
        for route in routes if route.path == "/api/explainability/{incident_id}"
    ) == "viewer"
    rows = []

    # FastAPI's built-in docs are Starlette Routes, so they have no dependant tree.
    # They remain token-protected by the same HTTP middleware and are included in the output.
    for route in http_routes:
        if isinstance(route, APIRoute):
            continue
        assert route.path in internal_docs_routes, f"Unexpected HTTP route without a dependant tree: {route.path}"
        for method in sorted(route.methods or ()):
            rows.append((route.path, method, "viewer (HTTP auth middleware)"))

    for route in routes:
        methods = sorted(route.methods or ())
        has_auth, role_sets, minimum_role = _route_auth_metadata(route)
        for method in methods:
            key = (method, route.path)
            if key in public:
                assert not has_auth, f"Public exception unexpectedly depends on analyst auth: {key}"
                minimum_role = "public"
            else:
                assert has_auth, f"{key} is missing get_current_analyst in its dependant tree"
            if method in {"POST", "PATCH", "PUT", "DELETE"} and key not in public:
                assert role_sets, f"Write route {key} has no role dependency"
                assert all("viewer" not in roles for roles in role_sets), (
                    f"Write route {key} permits viewer: {role_sets}"
                )
                if key in admin_only:
                    assert all(roles == {"admin"} for roles in role_sets), (
                        f"{key} must be admin-only, got {role_sets}"
                    )
                else:
                    assert minimum_role in {"analyst", "admin"}, (
                        f"Write route {key} requires analyst or admin, got {minimum_role}"
                    )
            rows.append((route.path, method, minimum_role))

    print("ROUTE AUTH TABLE (path | method | minimum role)")
    for path, method, role in sorted(rows):
        print(f"{path} | {method} | {role}")

