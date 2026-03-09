"""Pydantic models for the audit trail system."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, model_validator

from argus_ops.models import ActionIntent


class RiskLevel(str, enum.Enum):
    """Risk classification for heal and write operations."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def level(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __ge__(self, other: "RiskLevel") -> bool:
        return self.level >= other.level

    def __gt__(self, other: "RiskLevel") -> bool:
        return self.level > other.level

    def __le__(self, other: "RiskLevel") -> bool:
        return self.level <= other.level

    def __lt__(self, other: "RiskLevel") -> bool:
        return self.level < other.level


class ApprovalRecord(BaseModel):
    """Approval metadata for a write operation."""

    method: str = "interactive"
    approved_by: str = ""
    approved_at: datetime | None = None
    reason: str = ""


class AuditRecord(BaseModel):
    """Argus-Ops operation log entry."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = ""
    role: str = ""
    session_id: str = ""
    request_id: str = ""
    source: str = ""
    action: str = ""
    intent: ActionIntent = ActionIntent.MUTATING
    http_method: str = ""
    path: str = ""
    target: str = ""
    resource: str = ""
    reason: str = ""
    ip_address: str = ""
    user_agent: str = ""
    status_code: int = 0
    risk_level: RiskLevel = RiskLevel.low
    approval: ApprovalRecord = Field(default_factory=ApprovalRecord)
    command: str = ""
    dry_run: bool = False
    result: dict[str, Any] = Field(default_factory=dict)
    rollback_command: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _sync_legacy_fields(self) -> "AuditRecord":
        if not self.resource and self.target:
            self.resource = self.target
        if not self.target and self.resource:
            self.target = self.resource
        return self


class K8sAuditEvent(BaseModel):
    """Parsed K8s API server audit log event."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user: str = ""
    source_ips: list[str] = Field(default_factory=list)
    verb: str = ""
    resource_kind: str = ""
    resource_name: str = ""
    namespace: str = ""
    response_code: int = 0
    request_uri: str = ""
    user_agent: str = ""
    argus_ops_record_id: str = ""
