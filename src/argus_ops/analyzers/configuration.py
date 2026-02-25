"""Configuration analyzer: missing metrics-server, audit logging, mixed runtimes."""

from __future__ import annotations

import logging
import uuid
from collections import Counter

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import Finding, FindingCategory, HealthSnapshot, InfraType, Severity

logger = logging.getLogger(__name__)


class ConfigurationAnalyzer(BaseAnalyzer):
    """Detects cluster configuration issues.

    Checks:
    - Missing metrics-server (kubectl top unavailable)
    - Mixed container runtimes across nodes
    - Workload imbalance (too many pods on one node)
    - Node boot ID changes (unexpected reboots)
    """

    @property
    def name(self) -> str:
        return "configuration"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.CONFIGURATION

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []
        max_pods_per_node = self.config.get("max_pods_per_node", 15)

        for snap in snapshots:
            if snap.collector_name != "kubernetes":
                continue

            data = snap.data
            nodes = data.get("nodes", [])
            pods = data.get("pods", [])

            # ---- Check for metrics-server ----
            deployments = data.get("deployments", [])
            has_metrics_server = any(
                d.get("name", "") in ("metrics-server", "metrics-server-v2")
                for d in deployments
            )
            if not has_metrics_server:
                # Also check pods for metrics-server
                has_metrics_pod = any(
                    "metrics-server" in p.get("name", "")
                    for p in pods
                )
                if not has_metrics_pod:
                    findings.append(
                        Finding(
                            finding_id=f"CONF-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.CONFIGURATION,
                            severity=Severity.MEDIUM,
                            title="Missing metrics-server",
                            description=(
                                "No metrics-server deployment detected. "
                                "'kubectl top' and HPA will not work without it."
                            ),
                            target="cluster",
                            infra_type=InfraType.KUBERNETES,
                            evidence=["metrics-server deployment: not found"],
                        )
                    )

            # ---- Check for mixed container runtimes ----
            runtimes: dict[str, list[str]] = {}
            for node in nodes:
                node_name = node.get("name", "")
                runtime = node.get("container_runtime", "")
                if runtime:
                    runtimes.setdefault(runtime, []).append(node_name)

            if len(runtimes) > 1:
                evidence = [f"{rt}: {', '.join(nds)}" for rt, nds in runtimes.items()]
                findings.append(
                    Finding(
                        finding_id=f"CONF-{uuid.uuid4().hex[:8]}",
                        category=FindingCategory.CONFIGURATION,
                        severity=Severity.LOW,
                        title=f"Mixed container runtimes ({len(runtimes)} versions)",
                        description=(
                            "Nodes are running different container runtime versions. "
                            "This can lead to inconsistent behavior."
                        ),
                        target="cluster",
                        infra_type=InfraType.KUBERNETES,
                        evidence=evidence,
                    )
                )

            # ---- Check for workload imbalance ----
            pod_per_node: Counter = Counter()
            for pod in pods:
                node_name = pod.get("node_name", "")
                if node_name:
                    pod_per_node[node_name] += 1

            if pod_per_node:
                avg = sum(pod_per_node.values()) / max(len(pod_per_node), 1)
                for node_name, count in pod_per_node.most_common():
                    if count > max_pods_per_node and count > avg * 1.5:
                        findings.append(
                            Finding(
                                finding_id=f"CONF-{uuid.uuid4().hex[:8]}",
                                category=FindingCategory.CONFIGURATION,
                                severity=Severity.MEDIUM,
                                title=f"Workload imbalance: {node_name} ({count} pods)",
                                description=(
                                    f"Node '{node_name}' is running {count} pods, "
                                    f"significantly above average ({avg:.0f}). "
                                    "This node is a potential single point of failure."
                                ),
                                target=f"node/{node_name}",
                                infra_type=InfraType.KUBERNETES,
                                evidence=[
                                    f"Pod count: {count}",
                                    f"Cluster average: {avg:.0f}",
                                ],
                            )
                        )

        return findings
