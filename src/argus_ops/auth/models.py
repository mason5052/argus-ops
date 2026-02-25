"""Pydantic models for authentication and authorization."""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Role(str, enum.Enum):
    """User roles with increasing permission levels."""

    viewer = "viewer"
    operator = "operator"
    admin = "admin"

    @property
    def level(self) -> int:
        """Numeric level for comparison (higher = more permissions)."""
        return {"viewer": 0, "operator": 1, "admin": 2}[self.value]

    def __ge__(self, other: Role) -> bool:
        return self.level >= other.level

    def __gt__(self, other: Role) -> bool:
        return self.level > other.level

    def __le__(self, other: Role) -> bool:
        return self.level <= other.level

    def __lt__(self, other: Role) -> bool:
        return self.level < other.level


class User(BaseModel):
    """Stored user account."""

    username: str
    password_hash: str
    role: Role = Role.viewer
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class Session(BaseModel):
    """Active user session with JWT-like token data."""

    username: str
    role: Role
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    token: str = ""


class AuthEvent(BaseModel):
    """Authentication event for security audit logging."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str  # login_success, login_failure, logout, role_escalation_attempt
    username: str
    ip_address: str = ""
    details: str = ""
