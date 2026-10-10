from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException

from .db import connect

KEY_PREFIX = "ash_"
ROLES = {"viewer", "operator", "admin", "platform_admin"}


@dataclass(frozen=True)
class Principal:
    organization_id: str | None
    role: str
    key_id: str | None = None


def issue_key(db, organization_id: str | None, role: str) -> tuple[str, str]:
    if role not in ROLES:
        raise ValueError("Unknown API key role")
    token = KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = secrets.token_urlsafe(12)
    db.execute(
        "INSERT INTO api_keys (id, organization_id, prefix, secret_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (key_id, organization_id, token[:12], hashlib.sha256(token.encode()).hexdigest(), role, datetime.now(timezone.utc).isoformat()),
    )
    return key_id, token


def authenticate(token: str | None) -> Principal:
    if not token or not token.startswith(KEY_PREFIX) or len(token) > 128:
        raise HTTPException(401, "A valid AgentShield API key is required.", headers={"WWW-Authenticate": "Bearer"})
    digest = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        row = db.execute("SELECT id, organization_id, role FROM api_keys WHERE secret_hash=? AND revoked_at IS NULL", (digest,)).fetchone()
    if row is None:
        raise HTTPException(401, "A valid AgentShield API key is required.", headers={"WWW-Authenticate": "Bearer"})
    return Principal(row["organization_id"], row["role"], row["id"])


def require_role(principal: Principal, *roles: str) -> None:
    if principal.role not in roles:
        raise HTTPException(403, "This API key does not have permission for that action.")
