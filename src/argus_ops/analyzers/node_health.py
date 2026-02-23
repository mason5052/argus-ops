"""Node health analyzer (NotReady, DiskPressure, MemoryPressure, PIDPressure)."""

from __future__ import annotations

import uuid

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import (
    Finding,
    FindingCategory,
    HealthSnapshot,
    InfraType,
    Severity,
)


class NodeHealthAnalyzer(BaseAnalyzer):
    """Detects unhealthy node conditions.

    Checks for NotReady nodes, DiskPressure, MemoryPressure,
    PIDPressure, and unschedulable nodes.
    """

    @property
    def name(self) -> str:
        return "node_health"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.NODE_HEALTH

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snapshot in snapshots:
            if snapshot.infra_type != InfraType.KUBERNETES:
                continue
            if "nodes" not in snapshot.data:
                continue

            for node in snapshot.data["nodes"]:
                findings.extend(self._check_node(node))

        return findings

    def _check_node(self, node: dict) -> list[Finding]:
        findings: list[Finding] = []
        name = node["name"]
        conditions = node.get("conditions", {})
        target = f"k8s://node/{name}"

        # Node NotReady
        ready_cond = conditions.get("Ready", {})
        if ready_cond.get("status") != "True":
            reason = ready_cond.get("reason", "Unknown")
            message = ready_cond.get("message", "No details available")
            findings.append(Finding(
                finding_id=f"NODE-{uuid.uuid4().hex[:8]}",
                category=self.category,
                severity=Severity.CRITICAL,
                title=f"Node NotReady: {name}",
                description=(
                    f"Node {name} is not in Ready state. "
                    f"Reason: {reason}. This means no new pods will be scheduled on this node "
                    f"and existing pods may be evicted."
                ),
                target=target,
                infra_type=InfraType.KUBERNETES,
                evidence=[
                    f"Ready status: {ready_cond.get('status', 'Unknown')}",
                    f"Reason: {reason}",
                    f"Message: {message}",
                    f"OS: {node.get('os', 'unknown')}",
                    f"Arch: {node.get('arch', 'unknown')}",
                ],
            ))

        # Pressure conditions (should be False when healthy)
        pressure_conditions = {
            "MemoryPressure": (
                Severity.HIGH,
                "Node is running low on memory. Pods may be evicted.",
            ),
            "DiskPressure": (
                Severity.HIGH,
                "Node is running low on disk space. Image pulls and pod creation may fail.",
            ),
            "PIDPressure": (
                Severity.MEDIUM,
                "Node is running low on process IDs. New containers may fail to start.",
            ),
        }

        for condition_name, (severity, desc_suffix) in pressure_conditions.items():
            cond = conditions.get(condition_name, {})
            if cond.get("status") == "True":
                findings.append(Finding(
                    finding_id=f"NODE-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=severity,
                    title=f"{condition_name}: {name}",
                    description=f"Node {name} has {condition_name}. {desc_suffix}",
                    target=target,
                    infra_type=InfraType.KUBERNETES,
                    evidence=[
                        f"{condition_name}: True",
                        f"Reason: {cond.get('reason', 'Unknown')}",
                        f"Message: {cond.get('message', 'N/A')}",
                    ],
                ))

        # Unschedulable (cordoned) node
        if node.get("unschedulable"):
            findings.append(Finding(
                finding_id=f"NODE-{uuid.uuid4().hex[:8]}",
                category=self.category,
                severity=Severity.LOW,
                title=f"Node cordoned: {name}",
                description=(
                    f"Node {name} is marked as unschedulable (cordoned). "
                    f"No new pods will be scheduled on this node."
                ),
                target=target,
                infra_type=InfraType.KUBERNETES,
                evidence=["Unschedulable: True"],
            ))

        return findings
