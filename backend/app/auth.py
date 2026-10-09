"""Signed bearer sessions and role dependencies for the gateway UI."""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from .config import settings

Role = Literal["admin", "member"]
_bearer = HTTPBearer(auto_error=False)
_auth_lock = threading.Lock()
_PBKDF2_WORK_FACTOR = 310_000


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=32,
        pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,30}[A-Za-z0-9])$",
    )
    password: str = Field(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        if not re.search(r"[a-z]", password):
            raise ValueError("Add at least one lowercase letter.")
        if not re.search(r"[A-Z]", password):
            raise ValueError("Add at least one uppercase letter.")
        if not re.search(r"\d", password):
            raise ValueError("Add at least one number.")
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValueError("Add at least one symbol.")
        return password


class SessionUser(BaseModel):
    username: str
    role: Role


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: SessionUser


def init_auth_db() -> None:
    directory = os.path.dirname(os.path.abspath(settings.db_path))
    os.makedirs(directory, exist_ok=True)
    with _auth_lock:
        connection = sqlite3.connect(settings.db_path, timeout=10)
        try:
            with connection:
                connection.execute(
                    """CREATE TABLE IF NOT EXISTS registered_users (
                        username TEXT PRIMARY KEY COLLATE NOCASE,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )"""
                )
        finally:
            connection.close()


def _configured_accounts() -> list[tuple[str, str, Role]]:
    accounts: list[tuple[str, str, Role]] = []
    if settings.admin_username and settings.admin_password:
        accounts.append((settings.admin_username, settings.admin_password, "admin"))
    if settings.member_username and settings.member_password:
        accounts.append((settings.member_username, settings.member_password, "member"))
    return accounts


def _registered_user(username: str) -> tuple[str, str] | None:
    with _auth_lock:
        connection = sqlite3.connect(settings.db_path, timeout=10)
        try:
            row = connection.execute(
                "SELECT username, password_hash FROM registered_users WHERE username = ?",
                (username,),
            ).fetchone()
            return (str(row[0]), str(row[1])) if row else None
        finally:
            connection.close()


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_WORK_FACTOR)
    return f"pbkdf2_sha256${_PBKDF2_WORK_FACTOR}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations, salt_hex, expected_hex = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual.hex(), expected_hex)
    except (ValueError, TypeError):
        return False


def _issue_token(username: str, role: Role) -> LoginResponse:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": username, "role": role, "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)},
        settings.jwt_secret,
        algorithm="HS256",
    )
    return LoginResponse(access_token=token, user=SessionUser(username=username, role=role))


def login(request: LoginRequest) -> LoginResponse:
    accounts = _configured_accounts()
    registered = _registered_user(request.username)
    if not accounts and registered is None:
        raise HTTPException(status_code=503, detail="Login is not configured. Set an admin account in the backend environment.")

    username_bytes = request.username.encode("utf-8")
    password_bytes = request.password.encode("utf-8")
    matched: tuple[str, Role] | None = None
    for username, password, role in accounts:
        valid_username = secrets.compare_digest(username_bytes, username.encode("utf-8"))
        valid_password = secrets.compare_digest(password_bytes, password.encode("utf-8"))
        if valid_username and valid_password:
            matched = (username, role)
    if matched is None and registered and _verify_password(request.password, registered[1]):
        matched = (registered[0], "member")

    if matched is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username, role = matched
    return _issue_token(username, role)


def register(request: RegisterRequest) -> LoginResponse:
    username = request.username
    username_key = username.casefold()
    if any(name.casefold() == username_key for name, _, _ in _configured_accounts()):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That username is already in use.")

    with _auth_lock:
        connection = sqlite3.connect(settings.db_path, timeout=10)
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT 1 FROM registered_users WHERE username = ?",
                (username,),
            ).fetchone()
            if existing:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That username is already in use.")
            connection.execute(
                "INSERT INTO registered_users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (
                    username,
                    _hash_password(request.password),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    return _issue_token(username, "member")


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> SessionUser:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign in to continue.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        payload = jwt.decode(credentials.credentials, settings.jwt_secret, algorithms=["HS256"])
        username = payload.get("sub")
        role = payload.get("role")
        if not isinstance(username, str) or role not in ("admin", "member"):
            raise unauthorized
        configured_identity = any(
            secrets.compare_digest(username.encode("utf-8"), account_name.encode("utf-8")) and account_role == role
            for account_name, _, account_role in _configured_accounts()
        )
        registered_identity = role == "member" and _registered_user(username) is not None
        if not configured_identity and not registered_identity:
            raise unauthorized
        return SessionUser(username=username, role=role)
    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise unauthorized from None


def require_admin(user: SessionUser = Depends(current_user)) -> SessionUser:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required.")
    return user