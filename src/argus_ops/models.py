"""Core data models for infrastructure monitoring."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InfraType(str, Enum):
    """Types of infrastructure that can be monitored."""

    KUBERNETES = "kubernetes"
    SSH_HOST = "ssh_host"
    DOCKER = "docker"
    PROMETHEUS = "prometheus"


class FindingCategory(str, Enum):
    """Categories of detected issues."""

    RESOURCE = "resource"
    POD_HEALTH = "pod_health"
    NODE_HEALTH = "node_health"
    CERTIFICATE = "certificate"
    SECURITY = "security"
    CONNECTIVITY = "connectivity"
    STORAGE = "storage"
    CRONJOB = "cronjob"
    NETWORK_POLICY = "network_policy"
    CONFIGURATION = "configuration"
    CUSTOM = "custom"


class HealthSnapshot(BaseModel):
    """Point-in-time infrastructure state from a collector."""

    collector_name: str
    infra_type: InfraType
    timestamp: datetime = Field(default_factory=_utcnow)
    target: str
    data: dict[str, Any] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)


class Finding(BaseModel):
    """A detected anomaly or issue from an analyzer."""

    finding_id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    target: str
    infra_type: InfraType
    evidence: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class Diagnosis(BaseModel):
    """AI-generated root cause analysis."""

    diagnosis_id: str
    finding_ids: list[str] = Field(default_factory=list)
    root_cause: str
    explanation: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    recommendations: list[str] = Field(default_factory=list)
    related_resources: list[str] = Field(default_factory=list)
    model_used: str = ""
    tokens_used: int = 0
    cost_usd: float = 0.0
    timestamp: datetime = Field(default_factory=_utcnow)


class Incident(BaseModel):
    """Full incident lifecycle record."""

    incident_id: str
    findings: list[Finding] = Field(default_factory=list)
    diagnosis: Diagnosis | None = None
    status: str = "open"
    created_at: datetime = Field(default_factory=_utcnow)
    resolved_at: datetime | None = None

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity among all findings."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if not self.findings:
            return Severity.INFO
        return max(self.findings, key=lambda f: order.index(f.severity)).severity
