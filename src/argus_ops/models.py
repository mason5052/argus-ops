"""Core data models for infrastructure monitoring and discovery."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

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
    HOST = "host"
    GIT = "git"
    TERRAFORM = "terraform"
    GITHUB = "github"
    AWS = "aws"


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
    capabilities: list[str] = Field(default_factory=list)


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


class Capability(BaseModel):
    """A discovered collector capability exposed to analyzers and planners."""

    name: str
    collector_name: str
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetType(str, Enum):
    """Types of discovered inventory assets."""

    HOST = "host"
    FILESYSTEM_ROOT = "filesystem_root"
    DIRECTORY = "directory"
    GIT_REPOSITORY = "git_repository"
    TERRAFORM_ROOT = "terraform_root"
    DOCKER_ENGINE = "docker_engine"
    DOCKER_CONTAINER = "docker_container"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    KUBERNETES_NAMESPACE = "kubernetes_namespace"
    AWS_PROFILE = "aws_profile"
    GITHUB_REPOSITORY = "github_repository"


class Asset(BaseModel):
    """A discovered infrastructure or code asset."""

    asset_id: str
    asset_type: AssetType
    name: str
    infra_type: InfraType
    labels: dict[str, str] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class Relation(BaseModel):
    """A directed relationship between two assets."""

    source_asset_id: str
    target_asset_id: str
    relation_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class InventorySnapshot(BaseModel):
    """A point-in-time inventory graph for a single collector."""

    snapshot_id: str
    collector_name: str
    timestamp: datetime = Field(default_factory=_utcnow)
    target: str
    capabilities: list[Capability] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionIntent(str, Enum):
    """High-level intent classification for a requested action."""

    READ_ONLY = "read_only"
    MUTATING = "mutating"


class VerificationCheck(BaseModel):
    """A post-change verification step."""

    name: str
    provider: str
    success_criteria: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkflowSpec(BaseModel):
    """A workflow-as-code structure describing a multi-step operation."""

    workflow_id: str
    name: str
    triggers: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutionPolicy(BaseModel):
    """A policy decision that constrains how an action may run."""

    name: str
    description: str = ""
    allow_direct_execution: bool = False
    require_approval: bool = True
    allowed_roles: list[str] = Field(default_factory=lambda: ["admin"])
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionPlan(BaseModel):
    """A structured plan produced by Argus-Ops before a change runs."""

    plan_id: str
    title: str
    summary: str
    intent: ActionIntent = ActionIntent.MUTATING
    impact_summary: str = ""
    target_assets: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    verification_checks: list[VerificationCheck] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    policies: list[ExecutionPolicy] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class VerificationResult(BaseModel):
    """The outcome of a verification provider after a plan is applied."""

    name: str
    provider: str
    status: str
    checked_at: datetime = Field(default_factory=_utcnow)
    details: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class PlanExecutionRecord(BaseModel):
    """A persisted record of a plan execution attempt."""

    execution_id: str = Field(default_factory=lambda: f"EXEC-{uuid4().hex[:8]}")
    plan_id: str
    actor: str = ""
    status: str
    execution_mode: str = ""
    approved: bool = False
    direct: bool = False
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None
    verification_results: list[VerificationResult] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

