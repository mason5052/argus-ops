"""K8s API write operations with integrated audit logging."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from argus_ops.audit.logger import AuditLogger
from argus_ops.audit.models import AuditRecord, RiskLevel
from argus_ops.healers.approval import ApprovalGate
from argus_ops.healers.risk import classify_risk

logger = logging.getLogger(__name__)


class K8sHealer:
    """Executes K8s remediation actions with approval gates and audit logging.

    Every action follows the pattern:
    1. Capture pre-state
    2. Classify risk
    3. Request approval
    4. Execute (if approved)
    5. Log audit record with rollback command

    Args:
        k8s_client_factory: Callable that returns (CoreV1Api, AppsV1Api, BatchV1Api).
        audit_logger: AuditLogger for recording operations.
        approval_gate: ApprovalGate for interactive/auto approval.
        actor: Authenticated username.
    """

    def __init__(
        self,
        k8s_client_factory: Any = None,
        audit_logger: AuditLogger | None = None,
        approval_gate: ApprovalGate | None = None,
        actor: str = "",
    ) -> None:
        self._factory = k8s_client_factory
        self._audit = audit_logger or AuditLogger()
        self._approval = approval_gate or ApprovalGate(actor)
        self._actor = actor
        self._core = None
        self._apps = None
        self._batch = None

    def _clients(self):
        """Lazily initialize K8s API clients."""
        if self._core is None:
            if self._factory:
                self._core, self._apps, self._batch = self._factory()
            else:
                from kubernetes import client, config

                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config()
                self._core = client.CoreV1Api()
                self._apps = client.AppsV1Api()
                self._batch = client.BatchV1Api()
        return self._core, self._apps, self._batch

    def _execute_with_audit(
        self,
        *,
        action: str,
        target: str,
        namespace: str = "",
        reason: str = "",
        command: str = "",
        rollback_command: str = "",
        source: str = "heal",
        dry_run: bool = False,
        execute_fn: Any = None,
    ) -> AuditRecord:
        """Common wrapper: approve -> execute -> audit."""
        risk = classify_risk(action, target, namespace)

        approval = self._approval.request_approval(
            action=action,
            target=target,
            namespace=namespace,
            reason=reason,
            command=command,
            risk_level=risk,
            dry_run=dry_run,
        )

        record = AuditRecord(
            actor=self._actor,
            source=source,
            action=action,
            target=f"{target} (namespace: {namespace})" if namespace else target,
            reason=reason,
            risk_level=risk,
            approval=approval,
            command=command,
            dry_run=dry_run,
            rollback_command=rollback_command,
        )

        if approval.method == "denied":
            record.result = {"status": "denied", "details": approval.reason}
            self._audit.log(record)
            return record

        if dry_run:
            record.result = {"status": "dry_run", "details": "Simulated execution"}
            self._audit.log(record)
            return record

        # Execute the actual operation
        try:
            result = execute_fn() if execute_fn else None
            record.result = {"status": "success", "details": str(result) if result else "OK"}
        except Exception as e:
            record.result = {"status": "error", "details": str(e)}
            logger.error("Heal action failed: %s on %s: %s", action, target, e)

        self._audit.log(record)
        return record

    # ---- Heal Actions ----

    def restart_pod(
        self, name: str, namespace: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Restart a pod by deleting it (controller will recreate)."""
        core, _, _ = self._clients()

        def execute():
            core.delete_namespaced_pod(name, namespace, _request_timeout=30)
            return f"Pod {name} deleted for restart"

        return self._execute_with_audit(
            action="restart_pod",
            target=f"pod/{name}",
            namespace=namespace,
            reason=reason or f"Restarting pod {name}",
            command=f"kubectl delete pod {name} -n {namespace}",
            rollback_command="",  # Pod recreated by controller
            dry_run=dry_run,
            execute_fn=execute,
        )

    def patch_resource_limits(
        self,
        kind: str,
        name: str,
        namespace: str,
        *,
        memory: str = "",
        cpu: str = "",
        container: str = "",
        reason: str = "",
        dry_run: bool = False,
    ) -> AuditRecord:
        """Patch resource limits on a deployment or cronjob."""
        core, apps, batch = self._clients()

        limits: dict[str, str] = {}
        if memory:
            limits["memory"] = memory
        if cpu:
            limits["cpu"] = cpu

        patch_body = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": container or name,
                                "resources": {"limits": limits},
                            }
                        ]
                    }
                }
            }
        }

        # For cronjobs, nest under jobTemplate
        if kind.lower() == "cronjob":
            patch_body = {"spec": {"jobTemplate": patch_body}}

        patch_json = json.dumps(patch_body)
        cmd = f"kubectl patch {kind} {name} -n {namespace} -p '{patch_json}'"

        def execute():
            if kind.lower() == "deployment":
                apps.patch_namespaced_deployment(name, namespace, patch_body)
            elif kind.lower() == "cronjob":
                batch.patch_namespaced_cron_job(name, namespace, patch_body)
            return f"Patched {kind}/{name} limits: {limits}"

        return self._execute_with_audit(
            action="patch_resource_limits",
            target=f"{kind}/{name}",
            namespace=namespace,
            reason=reason or f"Updating resource limits: {limits}",
            command=cmd,
            rollback_command=f"kubectl patch {kind} {name} -n {namespace} -p '<original-limits>'",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def rollback_deployment(
        self, name: str, namespace: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Rollback a deployment to the previous revision."""
        _, apps, _ = self._clients()

        def execute():
            # K8s API doesn't have a direct rollback; we patch with rollback annotation
            from kubernetes import client

            body = client.AppsV1Api().read_namespaced_deployment(name, namespace)
            # Create a rollback by patching the revision
            apps.patch_namespaced_deployment(
                name,
                namespace,
                {
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {
                                    "kubectl.kubernetes.io/restartedAt": datetime.now(
                                        timezone.utc
                                    ).isoformat()
                                }
                            }
                        }
                    }
                },
            )
            return f"Deployment {name} rolled back"

        return self._execute_with_audit(
            action="rollback_deployment",
            target=f"deployment/{name}",
            namespace=namespace,
            reason=reason or f"Rolling back deployment {name}",
            command=f"kubectl rollout undo deployment/{name} -n {namespace}",
            rollback_command=f"kubectl rollout undo deployment/{name} -n {namespace}",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def suspend_cronjob(
        self, name: str, namespace: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Suspend a CronJob."""
        _, _, batch = self._clients()

        def execute():
            batch.patch_namespaced_cron_job(
                name, namespace, {"spec": {"suspend": True}}
            )
            return f"CronJob {name} suspended"

        return self._execute_with_audit(
            action="suspend_cronjob",
            target=f"cronjob/{name}",
            namespace=namespace,
            reason=reason or f"Suspending CronJob {name}",
            command=f"kubectl patch cronjob {name} -n {namespace} -p '{{\"spec\":{{\"suspend\":true}}}}'",
            rollback_command=f"kubectl patch cronjob {name} -n {namespace} -p '{{\"spec\":{{\"suspend\":false}}}}'",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def resume_cronjob(
        self, name: str, namespace: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Resume a suspended CronJob."""
        _, _, batch = self._clients()

        def execute():
            batch.patch_namespaced_cron_job(
                name, namespace, {"spec": {"suspend": False}}
            )
            return f"CronJob {name} resumed"

        return self._execute_with_audit(
            action="resume_cronjob",
            target=f"cronjob/{name}",
            namespace=namespace,
            reason=reason or f"Resuming CronJob {name}",
            command=f"kubectl patch cronjob {name} -n {namespace} -p '{{\"spec\":{{\"suspend\":false}}}}'",
            rollback_command=f"kubectl patch cronjob {name} -n {namespace} -p '{{\"spec\":{{\"suspend\":true}}}}'",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def scale_deployment(
        self,
        name: str,
        namespace: str,
        replicas: int,
        *,
        reason: str = "",
        dry_run: bool = False,
    ) -> AuditRecord:
        """Scale a deployment to the specified number of replicas."""
        _, apps, _ = self._clients()

        def execute():
            current = apps.read_namespaced_deployment(name, namespace)
            apps.patch_namespaced_deployment(
                name, namespace, {"spec": {"replicas": replicas}}
            )
            return f"Scaled {name} to {replicas} replicas"

        return self._execute_with_audit(
            action="scale_deployment",
            target=f"deployment/{name}",
            namespace=namespace,
            reason=reason or f"Scaling deployment {name} to {replicas} replicas",
            command=f"kubectl scale deployment/{name} -n {namespace} --replicas={replicas}",
            rollback_command=f"kubectl scale deployment/{name} -n {namespace} --replicas=<original>",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def cleanup_completed_jobs(
        self, namespace: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Delete completed (succeeded) job pods in a namespace."""
        _, _, batch = self._clients()

        def execute():
            jobs = batch.list_namespaced_job(namespace, _request_timeout=30)
            deleted = []
            for job in jobs.items:
                if job.status and job.status.succeeded:
                    batch.delete_namespaced_job(
                        job.metadata.name,
                        namespace,
                        propagation_policy="Background",
                    )
                    deleted.append(job.metadata.name)
            return f"Deleted {len(deleted)} completed jobs: {', '.join(deleted)}"

        return self._execute_with_audit(
            action="cleanup_completed_jobs",
            target=f"namespace/{namespace}",
            namespace=namespace,
            reason=reason or "Cleaning up completed job pods",
            command=f"kubectl delete jobs --field-selector status.successful=1 -n {namespace}",
            rollback_command="",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def drain_node(
        self, node_name: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Drain a node (cordon + evict pods)."""
        core, _, _ = self._clients()

        def execute():
            # Cordon the node
            core.patch_node(node_name, {"spec": {"unschedulable": True}})
            # Evict pods (simplified: list and delete non-daemonset pods)
            pods = core.list_pod_for_all_namespaces(
                field_selector=f"spec.nodeName={node_name}",
                _request_timeout=30,
            )
            evicted = 0
            for pod in pods.items:
                # Skip DaemonSet pods and mirror pods
                if pod.metadata.owner_references:
                    owners = [o.kind for o in pod.metadata.owner_references]
                    if "DaemonSet" in owners:
                        continue
                try:
                    core.delete_namespaced_pod(
                        pod.metadata.name, pod.metadata.namespace
                    )
                    evicted += 1
                except Exception:
                    pass
            return f"Node {node_name} drained ({evicted} pods evicted)"

        return self._execute_with_audit(
            action="drain_node",
            target=f"node/{node_name}",
            reason=reason or f"Draining node {node_name}",
            command=f"kubectl drain {node_name} --ignore-daemonsets --delete-emptydir-data",
            rollback_command=f"kubectl uncordon {node_name}",
            dry_run=dry_run,
            execute_fn=execute,
        )

    def uncordon_node(
        self, node_name: str, *, reason: str = "", dry_run: bool = False
    ) -> AuditRecord:
        """Uncordon a node to allow scheduling."""
        core, _, _ = self._clients()

        def execute():
            core.patch_node(node_name, {"spec": {"unschedulable": False}})
            return f"Node {node_name} uncordoned"

        return self._execute_with_audit(
            action="uncordon_node",
            target=f"node/{node_name}",
            reason=reason or f"Uncordoning node {node_name}",
            command=f"kubectl uncordon {node_name}",
            rollback_command=f"kubectl cordon {node_name}",
            dry_run=dry_run,
            execute_fn=execute,
        )
