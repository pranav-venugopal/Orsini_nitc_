"""Signed bearer sessions and role dependencies for the gateway UI."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from .config import settings

Role = Literal["admin", "member"]
_bearer = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class SessionUser(BaseModel):
    username: str
    role: Role


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    user: SessionUser


def _accounts() -> list[tuple[str, str, Role]]:
    accounts: list[tuple[str, str, Role]] = []
    if settings.admin_username and settings.admin_password:
        accounts.append((settings.admin_username, settings.admin_password, "admin"))
    if settings.member_username and settings.member_password:
        accounts.append((settings.member_username, settings.member_password, "member"))
    return accounts


def login(request: LoginRequest) -> LoginResponse:
    accounts = _accounts()
    if not accounts:
        raise HTTPException(status_code=503, detail="Login is not configured. Set an admin account in the backend environment.")

    username_bytes = request.username.encode("utf-8")
    password_bytes = request.password.encode("utf-8")
    matched: tuple[str, Role] | None = None
    for username, password, role in accounts:
        valid_username = secrets.compare_digest(username_bytes, username.encode("utf-8"))
        valid_password = secrets.compare_digest(password_bytes, password.encode("utf-8"))
        if valid_username and valid_password:
            matched = (username, role)

    if matched is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username, role = matched
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": username, "role": role, "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes)},
        settings.jwt_secret,
        algorithm="HS256",
    )
    return LoginResponse(access_token=token, user=SessionUser(username=username, role=role))


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
        if not any(account_name == username and account_role == role for account_name, _, account_role in _accounts()):
            raise unauthorized
        return SessionUser(username=username, role=role)
    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise unauthorized from None


def require_admin(user: SessionUser = Depends(current_user)) -> SessionUser:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access is required.")
    return user