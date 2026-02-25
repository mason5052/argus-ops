"""Pydantic models for the dual audit trail system."""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, enum.Enum):
    """Risk classification for heal / write operations."""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def level(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __ge__(self, other: RiskLevel) -> bool:
        return self.level >= other.level

    def __gt__(self, other: RiskLevel) -> bool:
        return self.level > other.level

    def __le__(self, other: RiskLevel) -> bool:
        return self.level <= other.level

    def __lt__(self, other: RiskLevel) -> bool:
        return self.level < other.level


class ApprovalRecord(BaseModel):
    """Approval metadata for a write operation."""

    method: str = "interactive"  # interactive, auto, denied
    approved_by: str = ""
    approved_at: datetime | None = None
    reason: str = ""


class AuditRecord(BaseModel):
    """Layer 1: Argus-Ops operation log entry (JSONL)."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = ""
    source: str = ""  # heal, chat, auto
    action: str = ""  # patch_resource_limits, restart_pod, etc.
    target: str = ""  # cronjob/rpa0004-01 (namespace: zrpa)
    reason: str = ""
    risk_level: RiskLevel = RiskLevel.low
    approval: ApprovalRecord = Field(default_factory=ApprovalRecord)
    command: str = ""  # kubectl command executed
    dry_run: bool = False
    result: dict[str, Any] = Field(default_factory=dict)
    rollback_command: str = ""


class K8sAuditEvent(BaseModel):
    """Layer 2: Parsed K8s API server audit log event."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user: str = ""  # K8s user or ServiceAccount
    source_ips: list[str] = Field(default_factory=list)
    verb: str = ""  # create, update, patch, delete
    resource_kind: str = ""
    resource_name: str = ""
    namespace: str = ""
    response_code: int = 0
    request_uri: str = ""
    user_agent: str = ""
    # correlation
    argus_ops_record_id: str = ""  # links to Layer 1 AuditRecord.id if matched
