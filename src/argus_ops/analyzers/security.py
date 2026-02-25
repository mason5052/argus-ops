"""Security analyzer: default ServiceAccounts, RBAC over-permissions, missing resource quotas."""

from __future__ import annotations

import logging
import uuid

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import Finding, FindingCategory, HealthSnapshot, InfraType, Severity

logger = logging.getLogger(__name__)

_SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}


class SecurityAnalyzer(BaseAnalyzer):
    """Detects security-related misconfigurations.

    Checks:
    - Pods using default ServiceAccount (no dedicated SA)
    - Namespaces without ResourceQuotas
    - Pods running as root / privileged containers
    - Pods with hostNetwork/hostPID/hostIPC enabled
    """

    @property
    def name(self) -> str:
        return "security"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.SECURITY

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snap in snapshots:
            if snap.collector_name != "kubernetes":
                continue

            data = snap.data
            pods = data.get("pods", [])
            namespaces = data.get("namespaces", [])
            resource_quotas = data.get("resource_quotas", [])

            # Track namespaces with ResourceQuotas
            quota_namespaces: set[str] = set()
            for rq in resource_quotas:
                ns = rq.get("namespace", "")
                if ns:
                    quota_namespaces.add(ns)

            # Check pods
            for pod in pods:
                pod_name = pod.get("name", "")
                pod_ns = pod.get("namespace", "")
                sa = pod.get("service_account", "default")
                security_context = pod.get("security_context", {})
                host_network = pod.get("host_network", False)
                host_pid = pod.get("host_pid", False)

                # Default ServiceAccount usage
                if sa == "default" and pod_ns not in _SYSTEM_NAMESPACES:
                    findings.append(
                        Finding(
                            finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.SECURITY,
                            severity=Severity.LOW,
                            title=f"Default ServiceAccount: {pod_name}",
                            description=(
                                f"Pod '{pod_name}' in namespace '{pod_ns}' uses the "
                                "default ServiceAccount. Dedicated ServiceAccounts "
                                "provide better access control."
                            ),
                            target=f"{pod_ns}/pod/{pod_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[f"ServiceAccount: {sa}"],
                        )
                    )

                # Privileged containers
                containers = pod.get("containers", [])
                for container in containers:
                    c_name = container.get("name", "")
                    c_sec = container.get("security_context", {})
                    if c_sec.get("privileged"):
                        findings.append(
                            Finding(
                                finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                                category=FindingCategory.SECURITY,
                                severity=Severity.HIGH,
                                title=f"Privileged container: {c_name}",
                                description=(
                                    f"Container '{c_name}' in pod '{pod_name}' "
                                    f"(namespace: {pod_ns}) runs in privileged mode."
                                ),
                                target=f"{pod_ns}/pod/{pod_name}/{c_name}",
                                infra_type=InfraType.KUBERNETES,
                                evidence=["privileged: true"],
                            )
                        )

                    if c_sec.get("run_as_user") == 0:
                        findings.append(
                            Finding(
                                finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                                category=FindingCategory.SECURITY,
                                severity=Severity.MEDIUM,
                                title=f"Root container: {c_name}",
                                description=(
                                    f"Container '{c_name}' in pod '{pod_name}' "
                                    f"(namespace: {pod_ns}) runs as root (UID 0)."
                                ),
                                target=f"{pod_ns}/pod/{pod_name}/{c_name}",
                                infra_type=InfraType.KUBERNETES,
                                evidence=["runAsUser: 0"],
                            )
                        )

                # Host namespace sharing
                if host_network:
                    findings.append(
                        Finding(
                            finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.SECURITY,
                            severity=Severity.MEDIUM,
                            title=f"hostNetwork enabled: {pod_name}",
                            description=(
                                f"Pod '{pod_name}' in namespace '{pod_ns}' uses "
                                "hostNetwork, sharing the node's network namespace."
                            ),
                            target=f"{pod_ns}/pod/{pod_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=["hostNetwork: true"],
                        )
                    )

            # Namespaces without ResourceQuotas
            for ns_info in namespaces:
                ns_name = ns_info if isinstance(ns_info, str) else ns_info.get("name", "")
                if ns_name in _SYSTEM_NAMESPACES:
                    continue
                if ns_name not in quota_namespaces:
                    findings.append(
                        Finding(
                            finding_id=f"SEC-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.SECURITY,
                            severity=Severity.LOW,
                            title=f"No ResourceQuota: namespace '{ns_name}'",
                            description=(
                                f"Namespace '{ns_name}' has no ResourceQuota. "
                                "Pods can consume unlimited resources."
                            ),
                            target=f"namespace/{ns_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=["ResourceQuotas: 0"],
                        )
                    )

        return findings
