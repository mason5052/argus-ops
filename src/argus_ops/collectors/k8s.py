"""Kubernetes infrastructure collector."""

from __future__ import annotations

import logging
import os
import re
import stat
import uuid
from typing import Any

from argus_ops.collectors.base import BaseCollector
from argus_ops.models import (
    Asset,
    AssetType,
    Capability,
    HealthSnapshot,
    InfraType,
    InventorySnapshot,
    Relation,
)

logger = logging.getLogger("argus_ops.collectors.k8s")

_EVENT_MESSAGE_MAX_LEN = 512
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(bearer\s+|token[=:\s]+)[A-Za-z0-9\-_.~+/]+=*"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(https?://[^:@\s]+:[^@\s]+@)"), r"[REDACTED]@"),
    (
        re.compile(r"\b(10\.\d{1,3}|\b172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        "[INTERNAL-IP]",
    ),
]


def _redact_event_message(message: str | None) -> str | None:
    if not message:
        return message
    for pattern, replacement in _REDACT_PATTERNS:
        message = pattern.sub(replacement, message)
    if len(message) > _EVENT_MESSAGE_MAX_LEN:
        message = message[:_EVENT_MESSAGE_MAX_LEN] + "...[truncated]"
    return message


class KubernetesCollector(BaseCollector):
    """Collect infrastructure state from Kubernetes into a contract-safe snapshot."""

    _API_TIMEOUT: int = 30

    @property
    def name(self) -> str:
        return "kubernetes"

    @property
    def infra_type(self) -> InfraType:
        return InfraType.KUBERNETES

    @property
    def provided_capabilities(self) -> list[str]:
        return [
            "k8s.cluster_inventory",
            "k8s.nodes",
            "k8s.pods",
            "k8s.deployments",
            "k8s.cronjobs",
            "k8s.services",
            "k8s.storage",
            "k8s.network_policies",
            "k8s.resource_quotas",
            "k8s.events",
        ]

    def is_available(self) -> bool:
        try:
            from kubernetes import client

            self._load_kubeconfig()
            client.VersionApi().get_code(_request_timeout=self._API_TIMEOUT)
            return True
        except Exception as exc:
            logger.debug("K8s API not available: %s", exc)
            return False

    def collect(self) -> list[HealthSnapshot]:
        from kubernetes import client

        self._load_kubeconfig()
        v1 = client.CoreV1Api()
        apps_v1 = client.AppsV1Api()
        batch_v1 = client.BatchV1Api()
        networking_v1 = client.NetworkingV1Api()

        namespaces = self._get_target_namespaces(v1)
        namespace_info = self._collect_namespaces(v1, namespaces)
        nodes = self._collect_nodes(v1)
        pods = self._collect_pods(v1, namespaces)
        events = self._collect_events(v1, namespaces)
        deployments = self._collect_deployments(apps_v1, namespaces)
        cronjobs = self._collect_cronjobs(batch_v1, namespaces)
        services = self._collect_services(v1, namespaces)
        persistent_volumes = self._collect_persistent_volumes(v1)
        persistent_volume_claims = self._collect_persistent_volume_claims(v1, namespaces)
        resource_quotas = self._collect_resource_quotas(v1, namespaces)
        network_policies = self._collect_network_policies(networking_v1, namespaces)

        metrics = {
            "nodes.total": float(len(nodes)),
            "pods.total": float(len(pods)),
            "deployments.total": float(len(deployments)),
            "cronjobs.total": float(len(cronjobs)),
            "services.total": float(len(services)),
            "events.warnings": float(len(events)),
        }

        return [
            HealthSnapshot(
                collector_name=self.name,
                infra_type=self.infra_type,
                target="k8s://cluster",
                data={
                    "namespaces": namespace_info,
                    "nodes": nodes,
                    "pods": pods,
                    "events": events,
                    "deployments": deployments,
                    "cronjobs": cronjobs,
                    "services": services,
                    "persistent_volumes": persistent_volumes,
                    "persistent_volume_claims": persistent_volume_claims,
                    "resource_quotas": resource_quotas,
                    "network_policies": network_policies,
                },
                metrics=metrics,
                capabilities=self.provided_capabilities,
            )
        ]

    def discover(self) -> InventorySnapshot | None:
        snapshots = self.collect()
        if not snapshots:
            return None
        snapshot = snapshots[0]
        assets = [
            Asset(
                asset_id="k8s:cluster",
                asset_type=AssetType.KUBERNETES_CLUSTER,
                name="kubernetes-cluster",
                infra_type=self.infra_type,
                properties={"target": snapshot.target},
            )
        ]
        relations: list[Relation] = []
        for namespace in snapshot.data.get("namespaces", []):
            ns_name = namespace.get("name", "")
            if not ns_name:
                continue
            asset_id = f"k8s:namespace:{ns_name}"
            assets.append(
                Asset(
                    asset_id=asset_id,
                    asset_type=AssetType.KUBERNETES_NAMESPACE,
                    name=ns_name,
                    infra_type=self.infra_type,
                    properties=namespace,
                )
            )
            relations.append(
                Relation(
                    source_asset_id="k8s:cluster",
                    target_asset_id=asset_id,
                    relation_type="contains",
                )
            )
        return InventorySnapshot(
            snapshot_id=f"INV-{uuid.uuid4().hex[:8]}",
            collector_name=self.name,
            target=snapshot.target,
            capabilities=[
                Capability(name=name, collector_name=self.name)
                for name in self.provided_capabilities
            ],
            assets=assets,
            relations=relations,
            metadata={"namespace_count": len(snapshot.data.get("namespaces", []))},
        )

    def _load_kubeconfig(self) -> None:
        from kubernetes import config as k8s_config

        kubeconfig = self.config.get("kubeconfig")
        context = self.config.get("context")

        if kubeconfig:
            try:
                mode = os.stat(kubeconfig).st_mode
                if mode & (stat.S_IRGRP | stat.S_IROTH):
                    logger.warning(
                        "kubeconfig %s is readable by group/others (mode %o). Consider chmod 600.",
                        kubeconfig,
                        stat.S_IMODE(mode),
                    )
            except OSError:
                pass

        try:
            k8s_config.load_kube_config(config_file=kubeconfig, context=context)
        except Exception:
            logger.warning(
                (
                    "Could not load kubeconfig (path=%s, context=%s), "
                    "falling back to in-cluster config"
                ),
                kubeconfig or "~/.kube/config",
                context or "current",
            )
            try:
                k8s_config.load_incluster_config()
            except Exception as exc:
                raise RuntimeError(f"Cannot load K8s config: {exc}") from exc

    def _get_target_namespaces(self, v1: Any) -> list[str]:
        configured_ns = self.config.get("namespaces", [])
        if configured_ns:
            return configured_ns

        exclude = set(self.config.get("exclude_namespaces", []))
        all_ns = v1.list_namespace(_request_timeout=self._API_TIMEOUT)
        return [ns.metadata.name for ns in all_ns.items if ns.metadata.name not in exclude]

    def _collect_namespaces(self, v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        ns_list = v1.list_namespace(_request_timeout=self._API_TIMEOUT)
        result = []
        allowed = set(namespaces)
        for namespace in ns_list.items:
            name = namespace.metadata.name
            if name not in allowed:
                continue
            result.append(
                {
                    "name": name,
                    "phase": getattr(namespace.status, "phase", "Active"),
                    "labels": namespace.metadata.labels or {},
                }
            )
        return result

    def _collect_nodes(self, v1: Any) -> list[dict[str, Any]]:
        nodes = v1.list_node(_request_timeout=self._API_TIMEOUT)
        node_data = []
        for node in nodes.items:
            conditions = {}
            for condition in node.status.conditions or []:
                conditions[condition.type] = {
                    "status": condition.status,
                    "reason": condition.reason,
                    "message": condition.message,
                }
            labels = node.metadata.labels or {}
            node_data.append(
                {
                    "name": node.metadata.name,
                    "conditions": conditions,
                    "labels": labels,
                    "allocatable": {
                        key: str(value)
                        for key, value in (node.status.allocatable or {}).items()
                    },
                    "capacity": {
                        key: str(value)
                        for key, value in (node.status.capacity or {}).items()
                    },
                    "os": labels.get("kubernetes.io/os", "unknown"),
                    "arch": labels.get("kubernetes.io/arch", "unknown"),
                    "unschedulable": node.spec.unschedulable or False,
                    "container_runtime": getattr(
                        getattr(node.status, "node_info", None),
                        "container_runtime_version",
                        "",
                    ),
                    "taints": [
                        {"key": taint.key, "value": taint.value, "effect": taint.effect}
                        for taint in (node.spec.taints or [])
                    ],
                }
            )
        return node_data

    def _collect_pods(self, v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        pod_data = []
        for namespace in namespaces:
            pods = v1.list_namespaced_pod(namespace, _request_timeout=self._API_TIMEOUT)
            for pod in pods.items:
                containers = []
                for container_status in pod.status.container_statuses or []:
                    state_info = self._parse_container_state(container_status.state)
                    container_spec = self._find_container_spec(pod, container_status.name)
                    containers.append(
                        {
                            "name": container_status.name,
                            "ready": container_status.ready,
                            "restart_count": container_status.restart_count,
                            "state": state_info,
                            "image": container_status.image,
                            "security_context": self._security_context_to_dict(
                                getattr(container_spec, "security_context", None)
                            ),
                        }
                    )
                pod_data.append(
                    {
                        "name": pod.metadata.name,
                        "namespace": namespace,
                        "phase": pod.status.phase or "Unknown",
                        "containers": containers,
                        "resources": self._pod_resources(pod),
                        "node_name": pod.spec.node_name,
                        "creation_timestamp": (
                            pod.metadata.creation_timestamp.isoformat()
                            if pod.metadata.creation_timestamp
                            else None
                        ),
                        "service_account": getattr(pod.spec, "service_account_name", "default"),
                        "security_context": self._security_context_to_dict(
                            getattr(pod.spec, "security_context", None)
                        ),
                        "host_network": bool(getattr(pod.spec, "host_network", False)),
                        "host_pid": bool(getattr(pod.spec, "host_pid", False)),
                        "host_ipc": bool(getattr(pod.spec, "host_ipc", False)),
                        "volumes": self._pod_volumes(pod),
                        "owner_kind": (
                            (pod.metadata.owner_references or [{}])[0].kind
                            if pod.metadata.owner_references
                            else ""
                        ),
                    }
                )
        return pod_data

    def _collect_events(self, v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        warning_events = []
        for namespace in namespaces:
            events = v1.list_namespaced_event(namespace, _request_timeout=self._API_TIMEOUT)
            for event in events.items:
                if event.type != "Warning":
                    continue
                warning_events.append(
                    {
                        "namespace": namespace,
                        "reason": event.reason,
                        "message": _redact_event_message(event.message),
                        "involved_object": {
                            "kind": event.involved_object.kind,
                            "name": event.involved_object.name,
                            "namespace": event.involved_object.namespace,
                        },
                        "count": event.count or 1,
                    }
                )
        return warning_events

    def _collect_deployments(self, apps_v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        deployments = []
        for namespace in namespaces:
            result = apps_v1.list_namespaced_deployment(
                namespace,
                _request_timeout=self._API_TIMEOUT,
            )
            for deployment in result.items:
                desired = deployment.spec.replicas or 0
                available = deployment.status.available_replicas or 0
                deployments.append(
                    {
                        "name": deployment.metadata.name,
                        "namespace": namespace,
                        "desired_replicas": desired,
                        "available_replicas": available,
                        "ready_replicas": deployment.status.ready_replicas or 0,
                        "updated_replicas": deployment.status.updated_replicas or 0,
                        "fully_available": available >= desired,
                    }
                )
        return deployments

    def _collect_cronjobs(self, batch_v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        cronjobs = []
        for namespace in namespaces:
            try:
                result = batch_v1.list_namespaced_cron_job(
                    namespace,
                    _request_timeout=self._API_TIMEOUT,
                )
            except Exception:
                continue
            for cronjob in result.items:
                cronjobs.append(
                    {
                        "name": cronjob.metadata.name,
                        "namespace": namespace,
                        "schedule": cronjob.spec.schedule,
                        "suspended": cronjob.spec.suspend or False,
                        "last_schedule_time": (
                            cronjob.status.last_schedule_time.isoformat()
                            if cronjob.status.last_schedule_time
                            else None
                        ),
                        "active_jobs": len(cronjob.status.active or []),
                        "failed_jobs_history_limit": cronjob.spec.failed_jobs_history_limit,
                    }
                )
        return cronjobs

    def _collect_services(self, v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        services = []
        for namespace in namespaces:
            result = v1.list_namespaced_service(namespace, _request_timeout=self._API_TIMEOUT)
            for service in result.items:
                services.append(
                    {
                        "name": service.metadata.name,
                        "namespace": namespace,
                        "type": service.spec.type,
                        "cluster_ip": service.spec.cluster_ip,
                        "ports": [
                            {
                                "port": port.port,
                                "protocol": port.protocol,
                                "target_port": str(port.target_port),
                            }
                            for port in (service.spec.ports or [])
                        ],
                        "selector": service.spec.selector or {},
                    }
                )
        return services

    def _collect_persistent_volumes(self, v1: Any) -> list[dict[str, Any]]:
        try:
            pvs = v1.list_persistent_volume(_request_timeout=self._API_TIMEOUT)
        except Exception:
            return []
        return [
            {
                "name": pv.metadata.name,
                "phase": pv.status.phase,
                "capacity": {key: str(value) for key, value in (pv.spec.capacity or {}).items()},
                "reclaim_policy": pv.spec.persistent_volume_reclaim_policy,
            }
            for pv in pvs.items
        ]

    def _collect_persistent_volume_claims(
        self,
        v1: Any,
        namespaces: list[str],
    ) -> list[dict[str, Any]]:
        pvcs = []
        for namespace in namespaces:
            try:
                result = v1.list_namespaced_persistent_volume_claim(
                    namespace,
                    _request_timeout=self._API_TIMEOUT,
                )
            except Exception:
                continue
            for pvc in result.items:
                pvcs.append(
                    {
                        "name": pvc.metadata.name,
                        "namespace": namespace,
                        "phase": pvc.status.phase,
                        "volume_name": pvc.spec.volume_name,
                    }
                )
        return pvcs

    def _collect_resource_quotas(self, v1: Any, namespaces: list[str]) -> list[dict[str, Any]]:
        quotas = []
        for namespace in namespaces:
            try:
                result = v1.list_namespaced_resource_quota(
                    namespace,
                    _request_timeout=self._API_TIMEOUT,
                )
            except Exception:
                continue
            for quota in result.items:
                quotas.append(
                    {
                        "name": quota.metadata.name,
                        "namespace": namespace,
                        "hard": {
                            key: str(value)
                            for key, value in (quota.status.hard or {}).items()
                        },
                    }
                )
        return quotas

    def _collect_network_policies(
        self,
        networking_v1: Any,
        namespaces: list[str],
    ) -> list[dict[str, Any]]:
        policies = []
        for namespace in namespaces:
            try:
                result = networking_v1.list_namespaced_network_policy(
                    namespace,
                    _request_timeout=self._API_TIMEOUT,
                )
            except Exception:
                continue
            for policy in result.items:
                policies.append(
                    {
                        "name": policy.metadata.name,
                        "namespace": namespace,
                        "policy_types": list(policy.spec.policy_types or []),
                        "ingress": [rule.to_dict() for rule in (policy.spec.ingress or [])],
                        "egress": [rule.to_dict() for rule in (policy.spec.egress or [])],
                    }
                )
        return policies

    @staticmethod
    def _parse_container_state(state: Any) -> dict[str, Any]:
        if state is None:
            return {"state": "unknown"}
        if state.running:
            return {
                "state": "running",
                "started_at": (
                    state.running.started_at.isoformat()
                    if state.running.started_at
                    else None
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
    def _security_context_to_dict(security_context: Any) -> dict[str, Any]:
        if security_context is None:
            return {}
        data = {}
        for field in (
            "privileged",
            "run_as_user",
            "run_as_non_root",
            "read_only_root_filesystem",
        ):
            value = getattr(security_context, field, None)
            if value is not None:
                data[field] = value
        return data

    @staticmethod
    def _pod_resources(pod: Any) -> dict[str, dict[str, dict[str, str]]]:
        resources: dict[str, dict[str, dict[str, str]]] = {}
        for container in pod.spec.containers or []:
            resources[container.name] = {
                "requests": {
                    key: str(value)
                    for key, value in (container.resources.requests or {}).items()
                },
                "limits": {
                    key: str(value)
                    for key, value in (container.resources.limits or {}).items()
                },
            }
        return resources

    @staticmethod
    def _pod_volumes(pod: Any) -> list[dict[str, Any]]:
        volumes = []
        for volume in pod.spec.volumes or []:
            item = {"name": volume.name, "type": "Unknown"}
            if volume.host_path:
                item.update({"type": "HostPath", "path": volume.host_path.path})
            elif volume.persistent_volume_claim:
                item.update(
                    {
                        "type": "PersistentVolumeClaim",
                        "claim_name": volume.persistent_volume_claim.claim_name,
                    }
                )
            volumes.append(item)
        return volumes

    @staticmethod
    def _find_container_spec(pod: Any, container_name: str) -> Any | None:
        for container in pod.spec.containers or []:
            if container.name == container_name:
                return container
        return None

    def validate_config(self) -> list[str]:
        errors = []
        namespaces = self.config.get("namespaces", [])
        exclude = self.config.get("exclude_namespaces", [])
        if namespaces and exclude:
            errors.append("Cannot specify both 'namespaces' and 'exclude_namespaces'")
        return errors
