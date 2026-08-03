from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from fastapi import Request


class AuthenticationError(Exception):
    """Raised when credentials are missing or invalid."""


class AuthorizationError(Exception):
    """Raised when authenticated role is not permitted."""


@dataclass(frozen=True)
class Principal:
    role: str


def _read_secret_from_value_or_file(
    value_env: str,
    file_env: str,
) -> str | None:
    inline = os.getenv(value_env)
    if inline:
        return inline.strip()
    file_path = os.getenv(file_env)
    if not file_path:
        return None
    path = Path(file_path)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8").strip() or None


class AuthService:
    def __init__(self) -> None:
        admin_token = _read_secret_from_value_or_file("LFS_ADMIN_TOKEN", "LFS_ADMIN_TOKEN_FILE")
        curator_token = _read_secret_from_value_or_file("LFS_CURATOR_TOKEN", "LFS_CURATOR_TOKEN_FILE")

        token_roles: dict[str, str] = {}
        if admin_token:
            token_roles[admin_token] = "admin"
        if curator_token:
            token_roles[curator_token] = "curator"
        self._token_roles = token_roles

    def authenticate(self, request: Request) -> Principal:
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            raise AuthenticationError("Missing bearer token")
        token = auth_header[7:].strip()
        role = self._token_roles.get(token)
        if role is None:
            raise AuthenticationError("Invalid bearer token")
        return Principal(role=role)

    def authorize(self, principal: Principal, allowed_roles: set[str]) -> None:
        if principal.role not in allowed_roles:
            raise AuthorizationError("Insufficient permissions")

