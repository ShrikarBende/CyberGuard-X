"""Password verification, signed analyst tokens, and role dependencies."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

import json
import threading
import time
from collections import deque
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.database.session import SessionLocal, get_db
from app.models.entities import AnalystAccount

LEGACY_PASSWORD_ITERATIONS = 310_000
ALLOWED_ROLES = {"viewer", "analyst", "admin"}
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60
bearer_scheme = HTTPBearer(auto_error=False)
_LOGIN_FAILURES: dict[tuple[str, str], deque[float]] = {}
_LOGIN_FAILURES_LOCK = threading.Lock()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii") + b"=" * (-len(value) % 4))


def normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = settings.PASSWORD_PBKDF2_ITERATIONS
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_text, expected_text = encoded.split("$", 3)
        iteration_count = int(iterations)
        if (algorithm != "pbkdf2_sha256" or iteration_count < LEGACY_PASSWORD_ITERATIONS
                or iteration_count > 10_000_000):
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(expected_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iteration_count)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def password_hash_needs_upgrade(encoded: str) -> bool:
    """Return whether a supported stored PBKDF2 hash predates current settings."""
    try:
        algorithm, iterations, _salt_text, _expected_text = encoded.split("$", 3)
        return algorithm != "pbkdf2_sha256" or int(iterations) < settings.PASSWORD_PBKDF2_ITERATIONS
    except (ValueError, TypeError):
        return True


def create_access_token(account: AnalystAccount) -> tuple[str, datetime]:
    issued = datetime.now(timezone.utc)
    expires = issued + timedelta(minutes=max(1, settings.ACCESS_TOKEN_MINUTES))
    payload = {
        "sub": account.username,
        "role": account.role,
        "iat": int(issued.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": uuid.uuid4().hex,
        "token_type": "access",
    }
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}", expires


def decode_access_token(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed signed token")
    signing_input = f"{parts[0]}.{parts[1]}"
    supplied_signature = _unb64url(parts[2])
    expected_signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise ValueError("Invalid token signature")
    header = json.loads(_unb64url(parts[0]))
    claims = json.loads(_unb64url(parts[1]))
    if header != {"alg": "HS256", "typ": "JWT"}:
        raise ValueError("Unsupported token header")
    if not isinstance(claims, dict):
        raise ValueError("Invalid token claims")
    for required in ("sub", "role", "iat", "exp", "token_type"):
        if required not in claims:
            raise ValueError("Missing token claim")
    now = int(datetime.now(timezone.utc).timestamp())
    if not isinstance(claims["exp"], int) or claims["exp"] <= now:
        raise ValueError("Expired token")
    if not isinstance(claims["iat"], int) or claims["iat"] > now + 30:
        raise ValueError("Invalid issue time")
    return claims


def account_for_token(token: str, db: Session) -> AnalystAccount | None:
    """Resolve a signed access token to its currently active account."""
    claims = decode_access_token(token)
    if claims.get("token_type") != "access" or claims.get("role") not in ALLOWED_ROLES:
        return None
    account = db.query(AnalystAccount).filter(
        AnalystAccount.username == claims["sub"],
        AnalystAccount.is_active.is_(True),
    ).first()
    if account is None or account.role != claims["role"]:
        return None
    return account


def _attempt_key(username: str, client_ip: str | None) -> tuple[str, str]:
    return normalize_username(username), client_ip or "unknown"


def login_is_limited(username: str, client_ip: str | None) -> bool:
    cutoff = time.monotonic() - LOGIN_FAILURE_WINDOW_SECONDS
    key = _attempt_key(username, client_ip)
    with _LOGIN_FAILURES_LOCK:
        attempts = _LOGIN_FAILURES.get(key)
        if attempts is None:
            return False
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if not attempts:
            _LOGIN_FAILURES.pop(key, None)
            return False
        return len(attempts) >= LOGIN_FAILURE_LIMIT


def record_failed_login(username: str, client_ip: str | None) -> None:
    cutoff = time.monotonic() - LOGIN_FAILURE_WINDOW_SECONDS
    key = _attempt_key(username, client_ip)
    with _LOGIN_FAILURES_LOCK:
        attempts = _LOGIN_FAILURES.setdefault(key, deque())
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        attempts.append(time.monotonic())


def clear_login_failures(username: str, client_ip: str | None) -> None:
    """Clear the lockout after a successful password verification."""
    key = _attempt_key(username, client_ip)
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES.pop(key, None)


def get_current_analyst(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AnalystAccount:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="A valid analyst bearer token is required.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized
    try:
        account = account_for_token(credentials.credentials, db)
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise unauthorized from exc
    if account is None:
        raise unauthorized
    return account


def require_roles(*roles: str) -> Callable:
    permitted = set(roles)

    def dependency(account: AnalystAccount = Depends(get_current_analyst)) -> AnalystAccount:
        if account.role not in permitted:
            raise HTTPException(status_code=403, detail="Your analyst role cannot perform this action.")
        return account

    dependency.required_roles = frozenset(permitted)
    return dependency


def ensure_bootstrap_admin() -> None:
    username = normalize_username(settings.ADMIN_USERNAME)
    password = settings.ADMIN_PASSWORD
    with SessionLocal() as db:
        if db.query(AnalystAccount.account_id).first() is not None:
            return
        if not username and not password:
            return
        if not username or not password:
            raise RuntimeError("Set both ADMIN_USERNAME and ADMIN_PASSWORD, or leave both empty.")
        if len(password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must contain at least 12 characters.")
        account = AnalystAccount(
            account_id=f"analyst_{uuid.uuid4().hex}",
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(account)
        db.commit()
