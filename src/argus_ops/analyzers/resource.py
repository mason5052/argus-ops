"""Resource utilization analyzer (CPU, memory, disk thresholds)."""

from __future__ import annotations

import uuid
from typing import Any

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import (
    Finding,
    FindingCategory,
    HealthSnapshot,
    InfraType,
    Severity,
)


class ResourceAnalyzer(BaseAnalyzer):
    """Detects resource utilization issues on K8s nodes.

    Checks CPU, memory, and disk usage against configurable thresholds
    and flags containers without resource limits.
    """

    @property
    def name(self) -> str:
        return "resource"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.RESOURCE

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snapshot in snapshots:
            if snapshot.infra_type != InfraType.KUBERNETES:
                continue

            if "nodes" in snapshot.data:
                findings.extend(self._check_node_resources(snapshot))
            if "pods" in snapshot.data:
                findings.extend(self._check_pod_resources(snapshot))

        return findings

    def _check_node_resources(self, snapshot: HealthSnapshot) -> list[Finding]:
        """Check node-level resource utilization."""
        findings: list[Finding] = []

        for node in snapshot.data.get("nodes", []):
            name = node["name"]
            allocatable = node.get("allocatable", {})
            capacity = node.get("capacity", {})

            # Check memory allocation ratio
            alloc_mem = self._parse_memory(allocatable.get("memory", "0"))
            cap_mem = self._parse_memory(capacity.get("memory", "0"))

            if cap_mem > 0 and alloc_mem > 0:
                mem_usage_ratio = 1.0 - (alloc_mem / cap_mem)
                mem_pct = mem_usage_ratio * 100

                if mem_pct >= self.config.get("memory_critical", 95):
                    findings.append(self._make_finding(
                        severity=Severity.CRITICAL,
                        title=f"Node {name}: memory critically low",
                        description=(
                            f"Node {name} has {mem_pct:.1f}% memory allocated. "
                            f"Allocatable: {self._format_bytes(alloc_mem)}, "
                            f"Capacity: {self._format_bytes(cap_mem)}"
                        ),
                        target=f"k8s://node/{name}",
                        evidence=[f"Memory allocation ratio: {mem_pct:.1f}%"],
                        metrics={"memory_allocation_pct": mem_pct},
                    ))
                elif mem_pct >= self.config.get("memory_warning", 85):
                    findings.append(self._make_finding(
                        severity=Severity.HIGH,
                        title=f"Node {name}: memory pressure building",
                        description=(
                            f"Node {name} has {mem_pct:.1f}% memory allocated. "
                            f"Consider scaling or redistributing workloads."
                        ),
                        target=f"k8s://node/{name}",
                        evidence=[f"Memory allocation ratio: {mem_pct:.1f}%"],
                        metrics={"memory_allocation_pct": mem_pct},
                    ))

        return findings

    def _check_pod_resources(self, snapshot: HealthSnapshot) -> list[Finding]:
        """Check for pods without resource limits."""
        findings: list[Finding] = []
        namespace = snapshot.data.get("namespace", "default")

        no_limits = []
        for pod in snapshot.data.get("pods", []):
            pod_name = pod["name"]
            resources = pod.get("resources", {})
            for container_name, res in resources.items():
                limits = res.get("limits", {})
                if not limits.get("memory") and not limits.get("cpu"):
                    no_limits.append(f"{pod_name}/{container_name}")

        if no_limits:
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                title=f"Namespace {namespace}: {len(no_limits)} container(s) without resource limits",  # noqa: E501
                description=(
                    "Containers without CPU/memory limits can consume unbounded resources "
                    "and cause node instability."
                ),
                target=f"k8s://{namespace}/pods",
                evidence=[f"No limits: {c}" for c in no_limits[:10]],
                metrics={"containers_without_limits": len(no_limits)},
            ))

        return findings

    def _make_finding(self, **kwargs: Any) -> Finding:
        return Finding(
            finding_id=f"RES-{uuid.uuid4().hex[:8]}",
            category=self.category,
            infra_type=InfraType.KUBERNETES,
            **kwargs,
        )

    @staticmethod
    def _parse_memory(mem_str: str) -> float:
        """Parse K8s memory string (e.g., '16Gi', '1024Mi') to bytes."""
        mem_str = mem_str.strip()
        if not mem_str or mem_str == "0":
            return 0.0

        units = {
            "Ki": 1024,
            "Mi": 1024**2,
            "Gi": 1024**3,
            "Ti": 1024**4,
            "k": 1000,
            "M": 1000**2,
            "G": 1000**3,
            "T": 1000**4,
        }

        for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
            if mem_str.endswith(suffix):
                try:
                    return float(mem_str[: -len(suffix)]) * multiplier
                except ValueError:
                    return 0.0

        try:
            return float(mem_str)
        except ValueError:
            return 0.0

    @staticmethod
    def _format_bytes(b: float) -> str:
        """Format bytes to human-readable string."""
        for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PiB"
