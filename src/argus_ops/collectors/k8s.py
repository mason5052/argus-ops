"""Kubernetes infrastructure collector."""

from __future__ import annotations

import logging
import os
import re
import stat
from typing import Any

from argus_ops.collectors.base import BaseCollector
from argus_ops.models import HealthSnapshot, InfraType

logger = logging.getLogger("argus_ops.collectors.k8s")

# Maximum length for event messages sent to AI providers
_EVENT_MESSAGE_MAX_LEN = 512

# Patterns that may contain sensitive infrastructure details
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bearer tokens and API keys
    (re.compile(r"(?i)(bearer\s+|token[=:\s]+)[A-Za-z0-9\-_.~+/]+=*"), r"\1[REDACTED]"),
    # Private registry credentials embedded in image pull errors
    (re.compile(r"(?i)(https?://[^:@\s]+:[^@\s]+@)"), r"[REDACTED]@"),
    # IPv4 addresses (internal RFC-1918 ranges)
    (re.compile(r"\b(10\.\d{1,3}|\b172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"), "[INTERNAL-IP]"),
]


def _redact_event_message(message: str | None) -> str | None:
    """Truncate and redact potentially sensitive content from event messages."""
    if not message:
        return message
    for pattern, replacement in _REDACT_PATTERNS:
        message = pattern.sub(replacement, message)
    if len(message) > _EVENT_MESSAGE_MAX_LEN:
        message = message[:_EVENT_MESSAGE_MAX_LEN] + "...[truncated]"
    return message


class KubernetesCollector(BaseCollector):
    """Collects infrastructure state from a Kubernetes cluster.

    Gathers node status, pod health, events, and resource usage
    via the official Kubernetes Python client.
    """

    @property
    def name(self) -> str:
        return "kubernetes"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.KUBERNETES

    # Default timeout (seconds) for all K8s API calls
    _API_TIMEOUT: int = 30

    def is_available(self) -> bool:
        """Check if we can connect to the K8s API server."""
        try:
            from kubernetes import client

            self._load_kubeconfig()
            v1 = client.VersionApi()
            v1.get_code(_request_timeout=self._API_TIMEOUT)
            return True
        except Exception as e:
            logger.debug("K8s API not available: %s", e)
            return False

    def collect(self) -> list[HealthSnapshot]:
        """Collect node, pod, event, and deployment state from K8s."""
        from kubernetes import client

        self._load_kubeconfig()
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        batch_v1 = client.BatchV1Api()

        snapshots = []
        namespaces = self._get_target_namespaces(v1)

        snapshots.append(self._collect_nodes(v1))
        for ns in namespaces:
            snapshots.append(self._collect_pods(v1, ns))
            snapshots.append(self._collect_events(v1, ns))
            snapshots.append(self._collect_deployments(apps_v1, ns))
            snapshots.append(self._collect_cronjobs(batch_v1, ns))

        return [s for s in snapshots if s is not None]

    def _load_kubeconfig(self) -> None:
        """Load kubeconfig from configured path or default."""
        from kubernetes import config as k8s_config

        kubeconfig = self.config.get("kubeconfig")
        context = self.config.get("context")

        # Warn if kubeconfig file has overly permissive permissions
        if kubeconfig:
            try:
                mode = os.stat(kubeconfig).st_mode
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    logger.warning(
                        "kubeconfig %s is readable by group/others (mode %o). "
                        "Consider running: chmod 600 %s",
                        kubeconfig,
                        stat.S_IMODE(mode),
                        kubeconfig,
                    )
            except OSError:
                pass

        try:
            k8s_config.load_kube_config(
                config_file=kubeconfig,
                context=context,
            )
        except Exception:
            logger.warning(
                "Could not load kubeconfig (path=%s, context=%s), "
                "falling back to in-cluster config",
                kubeconfig or "~/.kube/config",
                context or "current",
            )
            try:
                k8s_config.load_incluster_config()
                logger.info("Using in-cluster service account credentials")
            except Exception as e:
                raise RuntimeError(f"Cannot load K8s config: {e}") from e

    def _get_target_namespaces(self, v1: Any) -> list[str]:
        """Get list of namespaces to scan."""
        configured_ns = self.config.get("namespaces", [])
        if configured_ns:
            return configured_ns

        exclude = set(self.config.get("exclude_namespaces", []))
        all_ns = v1.list_namespace(_request_timeout=self._API_TIMEOUT)
        return [
            ns.metadata.name
            for ns in all_ns.items
            if ns.metadata.name not in exclude
        ]

    def _collect_nodes(self, v1: Any) -> HealthSnapshot:
        """Collect node status and resource info."""
        nodes = v1.list_node(_request_timeout=self._API_TIMEOUT)
        node_data = []
        metrics: dict[str, float] = {}

        for node in nodes.items:
            name = node.metadata.name
            conditions = {}
            for cond in (node.status.conditions or []):
                conditions[cond.type] = {
                    "status": cond.status,
                    "reason": cond.reason,
                    "message": cond.message,
                }

            labels = node.metadata.labels or {}
            allocatable = node.status.allocatable or {}
            capacity = node.status.capacity or {}

            node_info = {
                "name": name,
                "conditions": conditions,
                "labels": labels,
                "allocatable": {k: str(v) for k, v in allocatable.items()},
                "capacity": {k: str(v) for k, v in capacity.items()},
                "os": labels.get("kubernetes.io/os", "unknown"),
                "arch": labels.get("kubernetes.io/arch", "unknown"),
                "unschedulable": node.spec.unschedulable or False,
            }

            taints = node.spec.taints or []
            node_info["taints"] = [
                {"key": t.key, "value": t.value, "effect": t.effect}
                for t in taints
            ]

            node_data.append(node_info)

            ready = conditions.get("Ready", {}).get("status") == "True"
            metrics[f"node.{name}.ready"] = 1.0 if ready else 0.0

        metrics["nodes.total"] = float(len(node_data))
        metrics["nodes.ready"] = sum(
            1.0 for n in node_data
            if n["conditions"].get("Ready", {}).get("status") == "True"
        )

        return HealthSnapshot(
            collector_name=self.name,
            infra_type=self.infra_type,
            target="k8s://nodes",
            data={"nodes": node_data},
            metrics=metrics,
        )

    def _collect_pods(self, v1: Any, namespace: str) -> HealthSnapshot:
        """Collect pod status for a namespace."""
        pods = v1.list_namespaced_pod(namespace, _request_timeout=self._API_TIMEOUT)
        pod_data = []
        metrics: dict[str, float] = {}

        running = 0
        pending = 0
        failed = 0
        crashloop = 0
        total_restarts = 0

        for pod in pods.items:
            name = pod.metadata.name
            phase = pod.status.phase or "Unknown"

            containers = []
            for cs in (pod.status.container_statuses or []):
                state_info = self._parse_container_state(cs.state)
                containers.append({
                    "name": cs.name,
                    "ready": cs.ready,
                    "restart_count": cs.restart_count,
                    "state": state_info,
                    "image": cs.image,
                })
                total_restarts += cs.restart_count
                if state_info.get("waiting_reason") == "CrashLoopBackOff":
                    crashloop += 1

            if phase == "Running":
                running += 1
            elif phase == "Pending":
                pending += 1
            elif phase == "Failed":
                failed += 1

            # Resource requests/limits from spec
            resources = {}
            for container in (pod.spec.containers or []):
                req = container.resources
                if req:
                    resources[container.name] = {
                        "requests": self._resource_dict(req.requests),
                        "limits": self._resource_dict(req.limits),
                    }

            pod_data.append({
                "name": name,
                "namespace": namespace,
                "phase": phase,
                "containers": containers,
                "resources": resources,
                "node_name": pod.spec.node_name,
                "creation_timestamp": (
                    pod.metadata.creation_timestamp.isoformat()
                    if pod.metadata.creation_timestamp else None
                ),
            })

        metrics[f"pods.{namespace}.total"] = float(len(pod_data))
        metrics[f"pods.{namespace}.running"] = float(running)
        metrics[f"pods.{namespace}.pending"] = float(pending)
        metrics[f"pods.{namespace}.failed"] = float(failed)
        metrics[f"pods.{namespace}.crashloop"] = float(crashloop)
        metrics[f"pods.{namespace}.total_restarts"] = float(total_restarts)

        return HealthSnapshot(
            collector_name=self.name,
            infra_type=self.infra_type,
            target=f"k8s://{namespace}/pods",
            data={"pods": pod_data, "namespace": namespace},
            metrics=metrics,
        )

    def _collect_events(self, v1: Any, namespace: str) -> HealthSnapshot:
        """Collect warning events from a namespace."""
        events = v1.list_namespaced_event(namespace, _request_timeout=self._API_TIMEOUT)
        warning_events = []

        for event in events.items:
            if event.type != "Warning":
                continue
            warning_events.append({
                "reason": event.reason,
                "message": _redact_event_message(event.message),
                "involved_object": {
                    "kind": event.involved_object.kind,
                    "name": event.involved_object.name,
                    "namespace": event.involved_object.namespace,
                },
                "count": event.count or 1,
                "first_timestamp": (
                    event.first_timestamp.isoformat()
                    if event.first_timestamp else None
                ),
                "last_timestamp": (
                    event.last_timestamp.isoformat()
                    if event.last_timestamp else None
                ),
            })

        return HealthSnapshot(
            collector_name=self.name,
            infra_type=self.infra_type,
            target=f"k8s://{namespace}/events",
            data={"events": warning_events, "namespace": namespace},
            metrics={f"events.{namespace}.warnings": float(len(warning_events))},
        )

    def _collect_deployments(self, apps_v1: Any, namespace: str) -> HealthSnapshot:
        """Collect deployment status for a namespace."""
        deployments = apps_v1.list_namespaced_deployment(
            namespace, _request_timeout=self._API_TIMEOUT
        )
        deploy_data = []

        for dep in deployments.items:
            name = dep.metadata.name
            desired = dep.spec.replicas or 0
            available = dep.status.available_replicas or 0
            ready = dep.status.ready_replicas or 0
            updated = dep.status.updated_replicas or 0

            deploy_data.append({
                "name": name,
                "namespace": namespace,
                "desired_replicas": desired,
                "available_replicas": available,
                "ready_replicas": ready,
                "updated_replicas": updated,
                "fully_available": available >= desired,
            })

        return HealthSnapshot(
            collector_name=self.name,
            infra_type=self.infra_type,
            target=f"k8s://{namespace}/deployments",
            data={"deployments": deploy_data, "namespace": namespace},
            metrics={
                f"deployments.{namespace}.total": float(len(deploy_data)),
                f"deployments.{namespace}.degraded": float(
                    sum(1 for d in deploy_data if not d["fully_available"])
                ),
            },
        )

    def _collect_cronjobs(self, batch_v1: Any, namespace: str) -> HealthSnapshot | None:
        """Collect CronJob status for a namespace."""
        try:
            cronjobs = batch_v1.list_namespaced_cron_job(
                namespace, _request_timeout=self._API_TIMEOUT
            )
        except Exception:
            return None

        if not cronjobs.items:
            return None

        cj_data = []
        for cj in cronjobs.items:
            name = cj.metadata.name
            suspended = cj.spec.suspend or False
            last_schedule = (
                cj.status.last_schedule_time.isoformat()
                if cj.status.last_schedule_time else None
            )
            active_count = len(cj.status.active or [])

            cj_data.append({
                "name": name,
                "namespace": namespace,
                "schedule": cj.spec.schedule,
                "suspended": suspended,
                "last_schedule_time": last_schedule,
                "active_jobs": active_count,
            })

        return HealthSnapshot(
            collector_name=self.name,
            infra_type=self.infra_type,
            target=f"k8s://{namespace}/cronjobs",
            data={"cronjobs": cj_data, "namespace": namespace},
            metrics={f"cronjobs.{namespace}.total": float(len(cj_data))},
        )

    @staticmethod
    def _parse_container_state(state: Any) -> dict[str, Any]:
        """Parse container state into a flat dict."""
        if state is None:
            return {"state": "unknown"}

        if state.running:
            return {
                "state": "running",
                "started_at": (
                    state.running.started_at.isoformat()
                    if state.running.started_at else None
                ),
            }
        if state.waiting:
            return {
                "state": "waiting",
                "waiting_reason": state.waiting.reason,
                "waiting_message": state.waiting.message,
            }
        if state.terminated:
            return {
                "state": "terminated",
                "terminated_reason": state.terminated.reason,
                "exit_code": state.terminated.exit_code,
            }
        return {"state": "unknown"}

    @staticmethod
    def _resource_dict(resources: Any) -> dict[str, str]:
        """Convert K8s resource quantities to string dict."""
        if not resources:
            return {}
        return {k: str(v) for k, v in resources.items()}

    def validate_config(self) -> list[str]:
        errors = []
        ns = self.config.get("namespaces", [])
        exclude = self.config.get("exclude_namespaces", [])
        if ns and exclude:
            errors.append("Cannot specify both 'namespaces' and 'exclude_namespaces'")
        return errors
