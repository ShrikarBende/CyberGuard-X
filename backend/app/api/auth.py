"""Analyst login and administrator-managed analyst accounts."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import record_analyst_activity
from app.auth import (
    clear_login_failures, create_access_token, get_current_analyst, hash_password,
    login_is_limited, normalize_username, password_hash_needs_upgrade,
    record_failed_login, require_roles,
    verify_password,
)
from app.database.session import get_db
from app.models.entities import AnalystAccount

router = APIRouter(prefix="/api/auth", tags=["Analyst Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class AnalystCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=128)
    role: Literal["viewer", "analyst", "admin"]


@router.get("/me")
def current_analyst(account: AnalystAccount = Depends(get_current_analyst)):
    return {"username": account.username, "role": account.role}


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    username = normalize_username(payload.username)
    client_ip = request.client.host if request.client else None
    if login_is_limited(username, client_ip):
        record_analyst_activity(
            db, "unknown", "login_rate_limited",
            target_entity="analyst_account",
            details={"client_ip": client_ip},
        )
        db.commit()
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again later.")
    account = db.query(AnalystAccount).filter(AnalystAccount.username == username).first()
    valid = bool(account and account.is_active and verify_password(payload.password, account.password_hash))
    if not valid:
        record_analyst_activity(
            db,
            account.username if account else "unknown",
            "login_failed",
            target_entity="analyst_account",
            target_id=account.account_id if account else None,
            details={"client_ip": client_ip},
        )
        db.commit()
        record_failed_login(username, client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid analyst credentials.")

    if password_hash_needs_upgrade(account.password_hash):
        account.password_hash = hash_password(payload.password)
    clear_login_failures(username, client_ip)
    token, expires_at = create_access_token(account)
    record_analyst_activity(
        db,
        account.username,
        "login_succeeded",
        target_entity="analyst_account",
        target_id=account.account_id,
        details={"role": account.role, "client_ip": client_ip},
    )
    db.commit()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "analyst": {"username": account.username, "role": account.role},
    }


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_analyst(
    payload: AnalystCreateRequest,
    db: Session = Depends(get_db),
    admin: AnalystAccount = Depends(require_roles("admin")),
):
    username = normalize_username(payload.username)
    account = AnalystAccount(
        account_id=f"analyst_{uuid.uuid4().hex}",
        username=username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(account)
    record_analyst_activity(
        db, admin.username, "analyst_created", "analyst_account", account.account_id,
        {"role": payload.role},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="That analyst username already exists.") from exc
    return {"account_id": account.account_id, "username": account.username, "role": account.role}
