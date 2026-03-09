"""Planning, governance, workflow, verification, and execution helpers."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from argus_ops.audit.models import RiskLevel
from argus_ops.models import (
    ActionIntent,
    ActionPlan,
    ExecutionPolicy,
    PlanExecutionRecord,
    VerificationCheck,
    VerificationResult,
    WorkflowSpec,
)

_MUTATING_KEYWORDS = {
    "apply",
    "change",
    "create",
    "delete",
    "deploy",
    "drain",
    "patch",
    "remove",
    "restart",
    "rollback",
    "scale",
    "suspend",
    "resume",
    "update",
}
_CRITICAL_KEYWORDS = {"delete", "destroy", "drop", "remove"}
_HIGH_RISK_KEYWORDS = {"rollback", "drain", "uncordon", "cordon", "rotate secret"}
_DIRECT_EXECUTION_HINTS = {"restart", "scale", "rollback", "drain", "uncordon", "cordon"}
_PROTECTED_TARGET_HINTS = {"argocd", "kube-system", "monitoring", "prod", "production"}
_GITOPS_FILE_HINTS = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "helm",
    "kustomization.yaml",
    "main.tf",
    "terraform.tfvars",
    "values.yaml",
}



def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PlanStore:
    """Persist plans, executions, workflow exports, and execution artifacts."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self.data_dir = Path(data_dir) if data_dir else Path.home() / ".argus-ops"
        self.plans_path = self.data_dir / "plans.jsonl"
        self.executions_path = self.data_dir / "plan-executions.jsonl"
        self.workflow_dir = self.data_dir / "workflow-exports"
        self.artifact_dir = self.data_dir / "artifacts"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.workflow_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.plans_path.touch(exist_ok=True)
        self.executions_path.touch(exist_ok=True)

    def save(self, plan: ActionPlan) -> None:
        self._append_jsonl(self.plans_path, plan.model_dump(mode="json"))

    def get(self, plan_id: str) -> ActionPlan | None:
        for payload in self._read_jsonl_reversed(self.plans_path):
            if payload.get("plan_id") == plan_id:
                return ActionPlan.model_validate(payload)
        return None

    def list_recent(self, limit: int = 20) -> list[ActionPlan]:
        plans: list[ActionPlan] = []
        for payload in self._read_jsonl_reversed(self.plans_path):
            plans.append(ActionPlan.model_validate(payload))
            if len(plans) >= limit:
                break
        return plans

    def save_execution(self, execution: PlanExecutionRecord) -> None:
        self._append_jsonl(self.executions_path, execution.model_dump(mode="json"))

    def list_executions(self, limit: int = 20) -> list[PlanExecutionRecord]:
        executions: list[PlanExecutionRecord] = []
        for payload in self._read_jsonl_reversed(self.executions_path):
            executions.append(PlanExecutionRecord.model_validate(payload))
            if len(executions) >= limit:
                break
        return executions

    def export_workflow(self, plan: ActionPlan, workflow: WorkflowSpec) -> Path:
        path = self.workflow_dir / f"{plan.plan_id.lower()}.yaml"
        path.write_text(
            yaml.safe_dump(workflow.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        return path

    def read_workflow_export(self, plan_id: str) -> dict[str, Any] | None:
        path = self.workflow_dir / f"{plan_id.lower()}.yaml"
        if not path.exists():
            return None
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return {"path": str(path), "content": payload}

    def write_artifact(self, plan_id: str, artifact_type: str, content: str) -> Path:
        path = self.artifact_dir / f"{plan_id.lower()}-{artifact_type}.md"
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")

    @staticmethod
    def _read_jsonl_reversed(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        payloads: list[dict[str, Any]] = []
        for line in reversed(path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            payloads.append(json.loads(line))
        return payloads

class AutomationService:
    """Build and apply structured action plans from natural language goals."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self.store = PlanStore(data_dir)

    def build_plan(
        self,
        goal: str,
        *,
        inventory_summary: dict[str, Any],
        findings: list[Any] | None = None,
        actor: str = "",
        execution_mode: str = "gitops",
        target_assets: list[str] | None = None,
    ) -> ActionPlan:
        intent = classify_intent(goal)
        risk = classify_risk(goal)
        targets = list(target_assets or self._infer_target_assets(goal, inventory_summary))
        if not targets:
            targets = [
                asset.get("asset_id", asset.get("name", "unknown"))
                for asset in inventory_summary.get("assets", [])[:3]
            ]

        repo_candidates = self._discover_repo_candidates(inventory_summary)
        protected_context = self._is_protected_context(goal, targets)
        selected_mode = self._normalize_mode(intent, execution_mode, protected_context, risk)
        verification_checks = self._build_verification_checks(selected_mode, protected_context)
        policies = self._build_policies(
            intent=intent,
            execution_mode=selected_mode,
            risk=risk,
            target_assets=targets,
            goal=goal,
            repo_candidates=repo_candidates,
            protected_context=protected_context,
        )

        plan = ActionPlan(
            plan_id=f"PLAN-{uuid.uuid4().hex[:8]}",
            title=self._build_title(goal, selected_mode),
            summary=goal.strip(),
            intent=intent,
            impact_summary=self._build_impact_summary(
                intent,
                selected_mode,
                targets,
                findings or [],
                protected_context,
            ),
            target_assets=targets,
            steps=self._build_steps(goal, intent, selected_mode, targets, repo_candidates),
            verification_checks=verification_checks,
            rollback_steps=self._build_rollback_steps(selected_mode, risk),
            policies=policies,
            metadata={
                "actor": actor,
                "execution_mode": selected_mode,
                "requested_execution_mode": execution_mode,
                "risk_level": risk.value,
                "finding_count": len(findings or []),
                "inventory_asset_count": len(inventory_summary.get("assets", [])),
                "protected_context": protected_context,
                "repo_candidates": repo_candidates,
                "governance_summary": self._build_governance_summary(policies),
            },
        )
        workflow = self._build_workflow_spec(plan, repo_candidates)
        workflow_path = self.store.export_workflow(plan, workflow)
        plan.metadata["workflow_export_path"] = str(workflow_path)
        plan.metadata["workflow_id"] = workflow.workflow_id
        self.store.save(plan)
        return plan

    def apply_plan(
        self,
        plan_id: str,
        *,
        actor: str,
        approve: bool = False,
        direct: bool = False,
    ) -> dict[str, Any]:
        plan = self.store.get(plan_id)
        if plan is None:
            raise ValueError(f"Plan '{plan_id}' not found")

        approval_required = any(policy.require_approval for policy in plan.policies)
        execution_mode = self._resolve_execution_mode(plan, direct)
        if plan.intent == ActionIntent.MUTATING and approval_required and not approve:
            return {
                "plan_id": plan.plan_id,
                "status": "approval_required",
                "execution_mode": execution_mode,
                "risk_level": plan.metadata.get("risk_level", RiskLevel.medium.value),
                "actor": actor,
                "approval_required": True,
                "workflow_export_path": plan.metadata.get("workflow_export_path", ""),
                "plan": plan.model_dump(mode="json"),
            }

        artifacts = self._build_execution_artifacts(plan, execution_mode, actor)
        verification_results = self._run_verification_checks(plan, execution_mode, artifacts)
        status = "completed"
        if any(result.status == "failed" for result in verification_results):
            status = "verification_failed"

        execution = PlanExecutionRecord(
            plan_id=plan.plan_id,
            actor=actor,
            status=status,
            execution_mode=execution_mode,
            approved=approve,
            direct=direct,
            completed_at=_utcnow(),
            verification_results=verification_results,
            artifacts=artifacts,
            metadata={
                "workflow_export_path": plan.metadata.get("workflow_export_path", ""),
                "governance_summary": plan.metadata.get("governance_summary", ""),
            },
        )
        self.store.save_execution(execution)
        return {
            "plan_id": plan.plan_id,
            "execution_id": execution.execution_id,
            "status": status,
            "execution_mode": execution_mode,
            "risk_level": plan.metadata.get("risk_level", RiskLevel.medium.value),
            "actor": actor,
            "approval_required": approval_required,
            "workflow_export_path": plan.metadata.get("workflow_export_path", ""),
            "artifacts": artifacts,
            "verification_results": [
                result.model_dump(mode="json")
                for result in verification_results
            ],
            "rollback_steps": list(plan.rollback_steps),
            "plan": plan.model_dump(mode="json"),
        }

    def list_execution_history(self, limit: int = 20) -> list[PlanExecutionRecord]:
        return self.store.list_executions(limit=limit)

    def export_workflow(self, plan_id: str) -> dict[str, Any]:
        export = self.store.read_workflow_export(plan_id)
        if export is None:
            raise ValueError(f"Workflow export for plan '{plan_id}' not found")
        return export

    def list_workflows(self) -> list[WorkflowSpec]:
        return [
            WorkflowSpec(
                workflow_id="inventory.refresh",
                name="Refresh infrastructure inventory",
                triggers=["schedule.hourly", "manual.dashboard"],
                steps=[
                    {"name": "discover_assets", "action": "inventory.discover"},
                    {"name": "store_snapshot", "action": "inventory.persist"},
                    {"name": "publish_events", "action": "inventory.notify"},
                ],
                metadata={"kind": "runbook", "auditable": True},
            ),
            WorkflowSpec(
                workflow_id="gitops.pull_request",
                name="Create GitOps pull request",
                triggers=["api.plan.mutating", "chatops.request"],
                steps=[
                    {"name": "select_repo", "action": "git.select_repository"},
                    {"name": "generate_patch", "action": "gitops.generate_patch"},
                    {"name": "render_change_request", "action": "gitops.render_change_request"},
                    {"name": "await_approval", "action": "approval.wait"},
                ],
                metadata={"kind": "workflow", "default_execution_mode": "gitops"},
            ),
            WorkflowSpec(
                workflow_id="rollout.progressive",
                name="Progressive rollout with metric gates",
                triggers=["api.apply", "manual.dashboard"],
                steps=[
                    {"name": "deploy_canary", "action": "rollout.canary"},
                    {"name": "check_metrics", "action": "verify.metrics"},
                    {"name": "promote_or_rollback", "action": "rollout.promote_or_rollback"},
                ],
                metadata={"kind": "rollout", "supports": ["canary", "blue-green", "weighted"]},
            ),
            WorkflowSpec(
                workflow_id="incident.timeline",
                name="Incident timeline and routing",
                triggers=["finding.created", "incident.updated"],
                steps=[
                    {"name": "correlate_changes", "action": "audit.correlate"},
                    {"name": "route_incident", "action": "routing.namespace_team"},
                    {"name": "auto_close", "action": "incident.auto_close"},
                ],
                metadata={"kind": "operations", "timeline": True},
            ),
            WorkflowSpec(
                workflow_id="workflow.export",
                name="Export plan workflow as code",
                triggers=["api.plan", "cli.plan"],
                steps=[
                    {"name": "render_yaml", "action": "workflow.render_yaml"},
                    {"name": "persist_export", "action": "workflow.persist"},
                ],
                metadata={"kind": "workflow-as-code", "output": "yaml"},
            ),
        ]

    def list_plugins(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "host",
                "kind": "collector",
                "module": "argus_ops.collectors.local.HostCollector",
                "capabilities": [
                    "host.identity",
                    "host.filesystem",
                    "host.network",
                    "host.process_runtime",
                ],
                "builtin": True,
            },
            {
                "name": "docker",
                "kind": "collector",
                "module": "argus_ops.collectors.local.DockerCollector",
                "capabilities": ["docker.engine", "docker.containers"],
                "builtin": True,
            },
            {
                "name": "git",
                "kind": "collector",
                "module": "argus_ops.collectors.local.GitRepoCollector",
                "capabilities": ["git.repositories", "github.remotes"],
                "builtin": True,
            },
            {
                "name": "terraform",
                "kind": "collector",
                "module": "argus_ops.collectors.local.TerraformCollector",
                "capabilities": ["terraform.roots"],
                "builtin": True,
            },
            {
                "name": "github",
                "kind": "collector",
                "module": "argus_ops.collectors.local.GitHubCollector",
                "capabilities": ["github.token", "github.repositories"],
                "builtin": True,
            },
            {
                "name": "aws",
                "kind": "collector",
                "module": "argus_ops.collectors.local.AWSCollector",
                "capabilities": ["aws.profiles"],
                "builtin": True,
            },
            {
                "name": "kubernetes",
                "kind": "collector",
                "module": "argus_ops.collectors.k8s.KubernetesCollector",
                "capabilities": ["k8s.cluster_inventory", "k8s.workloads", "k8s.network_policies"],
                "builtin": True,
            },
            {
                "name": "resource",
                "kind": "analyzer",
                "module": "argus_ops.analyzers.resource.ResourceAnalyzer",
                "required_capabilities": ["k8s.cluster_inventory"],
                "builtin": True,
            },
            {
                "name": "pod_health",
                "kind": "analyzer",
                "module": "argus_ops.analyzers.pod_health.PodHealthAnalyzer",
                "required_capabilities": ["k8s.cluster_inventory"],
                "builtin": True,
            },
            {
                "name": "policy_engine",
                "kind": "governance",
                "module": "argus_ops.automation.AutomationService",
                "status": "active",
                "builtin": True,
            },
            {
                "name": "gitops_executor",
                "kind": "executor",
                "module": "argus_ops.automation.AutomationService",
                "status": "scaffold",
                "builtin": True,
            },
            {
                "name": "verification_providers",
                "kind": "verification",
                "module": "argus_ops.automation.AutomationService",
                "providers": ["inventory", "policy", "gitops", "metrics", "pipeline"],
                "builtin": True,
            },
            {
                "name": "progressive_rollout",
                "kind": "workflow_pack",
                "module": "argus_ops.automation.AutomationService",
                "status": "scaffold",
                "builtin": True,
            },
            {
                "name": "chatops_adapter",
                "kind": "connector_pack",
                "module": "argus_ops.automation.AutomationService",
                "status": "scaffold",
                "builtin": True,
            },
            {
                "name": "workflow_exporter",
                "kind": "workflow-as-code",
                "module": "argus_ops.automation.AutomationService",
                "status": "active",
                "builtin": True,
            },
        ]

    @staticmethod
    def _normalize_mode(
        intent: ActionIntent,
        requested_mode: str,
        protected_context: bool,
        risk: RiskLevel,
    ) -> str:
        if intent == ActionIntent.READ_ONLY:
            return "read-only"
        if protected_context or risk == RiskLevel.critical:
            return "gitops"
        if requested_mode == "direct":
            return "direct"
        return "gitops"

    @staticmethod
    def _build_title(goal: str, execution_mode: str) -> str:
        words = " ".join(goal.strip().split())
        shortened = words[:80].rstrip()
        if not shortened:
            shortened = "Untitled request"
        return f"{execution_mode.upper()} plan: {shortened}"

    @staticmethod
    def _build_impact_summary(
        intent: ActionIntent,
        execution_mode: str,
        target_assets: list[str],
        findings: list[Any],
        protected_context: bool,
    ) -> str:
        protection = " Protected targets detected." if protected_context else ""
        if intent == ActionIntent.READ_ONLY:
            return (
                f"Read-only request across {len(target_assets)} target asset(s). "
                f"No runtime mutation is planned.{protection}"
            )
        return (
            f"Mutating request against {len(target_assets)} target asset(s) "
            f"using {execution_mode} execution. "
            f"Related findings in scope: {len(findings)}.{protection}"
        )

    @staticmethod
    def _build_steps(
        goal: str,
        intent: ActionIntent,
        execution_mode: str,
        target_assets: list[str],
        repo_candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if intent == ActionIntent.READ_ONLY:
            return [
                {"name": "refresh_inventory", "action": "inventory.refresh", "goal": goal},
                {
                    "name": "correlate_findings",
                    "action": "analysis.correlate_findings",
                    "targets": target_assets,
                },
                {
                    "name": "summarize_response",
                    "action": "response.render",
                    "targets": target_assets,
                },
            ]
        if execution_mode == "direct":
            return [
                {"name": "preflight", "action": "execute.preflight", "goal": goal},
                {
                    "name": "approval_checkpoint",
                    "action": "approval.wait",
                    "targets": target_assets,
                },
                {"name": "execute_change", "action": "execute.direct", "targets": target_assets},
                {
                    "name": "verify_runtime",
                    "action": "verify.runtime_health",
                    "targets": target_assets,
                },
            ]
        return [
            {
                "name": "select_repository",
                "action": "git.repository.select",
                "goal": goal,
                "candidates": repo_candidates,
            },
            {"name": "generate_patch", "action": "gitops.generate_patch", "targets": target_assets},
            {
                "name": "render_change_request",
                "action": "gitops.render_change_request",
                "targets": target_assets,
            },
            {"name": "await_approval", "action": "approval.wait", "targets": target_assets},
            {"name": "sync_runtime", "action": "gitops.sync_runtime", "targets": target_assets},
        ]

    @staticmethod
    def _build_verification_checks(
        execution_mode: str,
        protected_context: bool,
    ) -> list[VerificationCheck]:
        checks = [
            VerificationCheck(
                name="inventory-refresh",
                provider="inventory",
                success_criteria="A fresh inventory snapshot is stored after the action.",
            ),
            VerificationCheck(
                name="policy-gates",
                provider="policy",
                success_criteria="Protected-target and admin-only policies remain satisfied.",
            ),
            VerificationCheck(
                name="health-scan",
                provider="pipeline",
                success_criteria=(
                    "Critical and high-severity findings do not increase "
                    "after the action."
                ),
            ),
        ]
        if execution_mode == "gitops":
            checks.append(
                VerificationCheck(
                    name="gitops-sync-health",
                    provider="gitops",
                    success_criteria=(
                        "Desired state and runtime state converge "
                        "without blocking drift."
                    ),
                )
            )
        else:
            checks.append(
                VerificationCheck(
                    name="rollout-metric-gate",
                    provider="metrics",
                    success_criteria="Metric gates remain healthy during and after rollout.",
                    metadata={"protected_context": protected_context},
                )
            )
        return checks

    @staticmethod
    def _build_rollback_steps(execution_mode: str, risk: RiskLevel) -> list[str]:
        if execution_mode == "gitops":
            return [
                "Revert the generated commit or close the pull request.",
                "Sync the runtime back to the previous desired state.",
            ]
        if risk >= RiskLevel.high:
            return [
                "Pause the rollout immediately.",
                "Restore the previous deployment or service configuration.",
            ]
        return ["Restore the previous runtime configuration snapshot."]

    def _build_policies(
        self,
        *,
        intent: ActionIntent,
        execution_mode: str,
        risk: RiskLevel,
        target_assets: list[str],
        goal: str,
        repo_candidates: list[dict[str, Any]],
        protected_context: bool,
    ) -> list[ExecutionPolicy]:
        if intent == ActionIntent.READ_ONLY:
            return [
                ExecutionPolicy(
                    name="viewer-read-only",
                    description="Read-only plans may be created by viewer and admin users.",
                    allow_direct_execution=False,
                    require_approval=False,
                    allowed_roles=["viewer", "admin"],
                )
            ]

        policies = [
            ExecutionPolicy(
                name="admin-change-control",
                description="Mutating plans are restricted to admin users and require approval.",
                allow_direct_execution=execution_mode == "direct" and risk < RiskLevel.critical,
                require_approval=True,
                allowed_roles=["admin"],
                metadata={"risk_level": risk.value},
            )
        ]
        if execution_mode == "gitops":
            policies.append(
                ExecutionPolicy(
                    name="gitops-preferred",
                    description=(
                        "Mutating changes should flow through GitOps artifacts "
                        "before runtime sync."
                    ),
                    allow_direct_execution=False,
                    require_approval=True,
                    allowed_roles=["admin"],
                    metadata={"repo_candidates": repo_candidates},
                )
            )
        if protected_context:
            policies.append(
                ExecutionPolicy(
                    name="protected-target-manual-approval",
                    description=(
                        "Protected namespaces and production targets cannot "
                        "bypass approval."
                    ),
                    allow_direct_execution=False,
                    require_approval=True,
                    allowed_roles=["admin"],
                    metadata={"targets": target_assets},
                )
            )
        if any(keyword in goal.lower() for keyword in _CRITICAL_KEYWORDS):
            policies.append(
                ExecutionPolicy(
                    name="destructive-action-control",
                    description=(
                        "Destructive actions require GitOps review and explicit "
                        "admin approval."
                    ),
                    allow_direct_execution=False,
                    require_approval=True,
                    allowed_roles=["admin"],
                    metadata={"targets": target_assets},
                )
            )
        return policies

    def _build_governance_summary(self, policies: list[ExecutionPolicy]) -> str:
        return "; ".join(policy.name for policy in policies)

    def _build_workflow_spec(
        self,
        plan: ActionPlan,
        repo_candidates: list[dict[str, Any]],
    ) -> WorkflowSpec:
        return WorkflowSpec(
            workflow_id=f"workflow.{plan.plan_id.lower()}",
            name=plan.title,
            triggers=[
                "manual.plan",
                "api.apply" if plan.intent == ActionIntent.MUTATING else "api.plan",
            ],
            steps=[
                {
                    "name": step.get("name", "step"),
                    "action": step.get("action", "unknown"),
                    "targets": step.get("targets", []),
                }
                for step in plan.steps
            ]
            + [
                {
                    "name": check.name,
                    "action": f"verify.{check.provider}",
                    "success_criteria": check.success_criteria,
                }
                for check in plan.verification_checks
            ],
            metadata={
                "plan_id": plan.plan_id,
                "execution_mode": plan.metadata.get("execution_mode", "gitops"),
                "repo_candidates": repo_candidates,
                "governance_summary": plan.metadata.get("governance_summary", ""),
            },
        )

    def _build_execution_artifacts(
        self,
        plan: ActionPlan,
        execution_mode: str,
        actor: str,
    ) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        workflow_path = plan.metadata.get("workflow_export_path")
        if workflow_path:
            artifacts.append(
                {
                    "type": "workflow_export",
                    "path": workflow_path,
                    "description": "Workflow-as-code export generated at plan time.",
                }
            )
        if execution_mode == "gitops":
            path = self.store.write_artifact(
                plan.plan_id,
                "change-request",
                self._render_gitops_change_request(plan, actor),
            )
            artifacts.append(
                {
                    "type": "change_request",
                    "path": str(path),
                    "description": "GitOps change request artifact",
                }
            )
        elif execution_mode == "direct":
            path = self.store.write_artifact(
                plan.plan_id,
                "runbook",
                self._render_direct_runbook(plan, actor),
            )
            artifacts.append(
                {
                    "type": "runbook",
                    "path": str(path),
                    "description": "Direct execution runbook artifact",
                }
            )
        return artifacts

    def _run_verification_checks(
        self,
        plan: ActionPlan,
        execution_mode: str,
        artifacts: list[dict[str, Any]],
    ) -> list[VerificationResult]:
        results: list[VerificationResult] = []
        for check in plan.verification_checks:
            if check.provider == "inventory":
                status = (
                    "passed"
                    if plan.metadata.get("inventory_asset_count", 0) >= 0
                    else "failed"
                )
                details = "Inventory baseline is available for comparison."
            elif check.provider == "policy":
                status = "passed"
                details = (
                    "Applied governance policies: "
                    f"{plan.metadata.get('governance_summary', '')}"
                )
            elif check.provider == "gitops":
                status = (
                    "passed"
                    if any(item["type"] == "change_request" for item in artifacts)
                    else "failed"
                )
                details = "GitOps artifact was exported for review."
            elif check.provider == "metrics":
                status = "pending"
                details = "Metric provider integration is scaffolded but not yet connected."
            else:
                status = "pending"
                details = (
                    "Post-change runtime re-scan integration is scaffolded "
                    "but not yet connected."
                )
            results.append(
                VerificationResult(
                    name=check.name,
                    provider=check.provider,
                    status=status,
                    details=details,
                    metadata=check.metadata,
                )
            )
        return results

    @staticmethod
    def _render_gitops_change_request(plan: ActionPlan, actor: str) -> str:
        repo_candidates = plan.metadata.get("repo_candidates", [])
        selected_repo = (
            repo_candidates[0]["path"]
            if repo_candidates
            else "No repository discovered"
        )
        lines = [
            f"# Change Request for {plan.plan_id}",
            "",
            f"Actor: {actor}",
            f"Title: {plan.title}",
            f"Summary: {plan.summary}",
            f"Selected repository: {selected_repo}",
            f"Governance summary: {plan.metadata.get('governance_summary', '')}",
            "",
            "## Planned Steps",
        ]
        lines.extend(
            f"- {step.get('name')}: {step.get('action')}"
            for step in plan.steps
        )
        lines.extend(
            [
                "",
                "## Suggested Diff Scope",
                (
                    "- Review Helm values, manifests, Terraform roots, "
                    "Dockerfiles, and workflow files."
                ),
                "- Create a pull request before applying runtime changes.",
                "",
                "## Verification",
            ]
        )
        lines.extend(
            f"- {check.name}: {check.success_criteria}"
            for check in plan.verification_checks
        )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_direct_runbook(plan: ActionPlan, actor: str) -> str:
        lines = [
            f"# Direct Runbook for {plan.plan_id}",
            "",
            f"Actor: {actor}",
            f"Title: {plan.title}",
            f"Summary: {plan.summary}",
            f"Governance summary: {plan.metadata.get('governance_summary', '')}",
            "",
            "## Ordered Checklist",
        ]
        lines.extend(
            f"- {step.get('name')}: {step.get('action')}"
            for step in plan.steps
        )
        lines.extend(["", "## Rollback"])
        lines.extend(f"- {step}" for step in plan.rollback_steps)
        return "\n".join(lines) + "\n"

    @staticmethod
    def _resolve_execution_mode(plan: ActionPlan, direct: bool) -> str:
        execution_mode = plan.metadata.get("execution_mode", "gitops")
        if direct and any(policy.allow_direct_execution for policy in plan.policies):
            return "direct"
        return execution_mode

    @staticmethod
    def _is_protected_context(goal: str, target_assets: list[str]) -> bool:
        combined = " ".join([goal, *target_assets]).lower()
        return any(hint in combined for hint in _PROTECTED_TARGET_HINTS)

    @staticmethod
    def _discover_repo_candidates(inventory_summary: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for asset in inventory_summary.get("assets", []):
            if asset.get("asset_type") != "git_repository":
                continue
            properties = asset.get("properties", {})
            candidates.append(
                {
                    "asset_id": asset.get("asset_id"),
                    "name": asset.get("name"),
                    "path": properties.get("path", ""),
                    "branch": properties.get("branch", ""),
                    "remote_url": properties.get("remote_url", ""),
                    "gitops_hints": AutomationService._repo_gitops_hints(
                        properties.get("path", "")
                    ),
                }
            )
        return candidates

    @staticmethod
    def _repo_gitops_hints(path_str: str) -> list[str]:
        if not path_str:
            return []
        root = Path(path_str)
        hints = []
        for name in _GITOPS_FILE_HINTS:
            if (root / name).exists():
                hints.append(name)
        return sorted(hints)

    @staticmethod
    def _infer_target_assets(goal: str, inventory_summary: dict[str, Any]) -> list[str]:
        matches: list[str] = []
        lower_goal = goal.lower()
        for asset in inventory_summary.get("assets", []):
            name = str(asset.get("name", "")).lower()
            asset_id = str(asset.get("asset_id", ""))
            if name and name in lower_goal:
                matches.append(asset_id or name)
        return matches

def classify_intent(goal: str) -> ActionIntent:
    """Classify a natural-language goal as read-only or mutating."""
    lower_goal = goal.lower()
    if any(keyword in lower_goal for keyword in _MUTATING_KEYWORDS):
        return ActionIntent.MUTATING
    return ActionIntent.READ_ONLY


def classify_risk(goal: str) -> RiskLevel:
    """Estimate risk from natural-language intent."""
    lower_goal = goal.lower()
    if any(keyword in lower_goal for keyword in _CRITICAL_KEYWORDS):
        return RiskLevel.critical
    if any(keyword in lower_goal for keyword in _HIGH_RISK_KEYWORDS):
        return RiskLevel.high
    if any(keyword in lower_goal for keyword in _MUTATING_KEYWORDS):
        return RiskLevel.medium
    return RiskLevel.low


def prefers_direct_execution(goal: str) -> bool:
    """Return True when the request sounds like an emergency runtime operation."""
    lower_goal = goal.lower()
    return any(keyword in lower_goal for keyword in _DIRECT_EXECUTION_HINTS)



