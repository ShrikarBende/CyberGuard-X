"""Administrative command line tools for analyst account setup."""
from __future__ import annotations

import getpass
import sys
import uuid

from sqlalchemy.exc import IntegrityError

from app.auth import hash_password, normalize_username
from app.database.session import SessionLocal
from app.models.entities import AnalystAccount


def create_admin() -> int:
    with SessionLocal() as db:
        if db.query(AnalystAccount.account_id).first() is not None:
            print("Admin creation refused: an analyst account already exists.", file=sys.stderr)
            return 1
    username = normalize_username(input("Admin username: "))
    if len(username) < 3 or len(username) > 64:
        print("Username must contain 3 to 64 characters.", file=sys.stderr)
        return 2
    password = getpass.getpass("Admin password (minimum 12 characters): ")
    confirmation = getpass.getpass("Confirm admin password: ")
    if len(password) < 12:
        print("Password must contain at least 12 characters.", file=sys.stderr)
        return 2
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        if db.query(AnalystAccount.account_id).first() is not None:
            print("Admin creation refused: an analyst account already exists.", file=sys.stderr)
            return 1
        account = AnalystAccount(
            account_id=f"analyst_{uuid.uuid4().hex}",
            username=username,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        db.add(account)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            print("Admin creation failed because an account was created concurrently.", file=sys.stderr)
            return 1
    print(f"Created initial admin account '{username}'.")
    return 0


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] != "create_admin":
        print("Usage: python -m app.cli create_admin", file=sys.stderr)
        return 2
    from app.main import run_database_migrations
    run_database_migrations()
    return create_admin()


if __name__ == "__main__":
    raise SystemExit(main())
