"""Pod health analyzer (CrashLoopBackOff, OOMKilled, Pending, ImagePull errors)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import (
    Finding,
    FindingCategory,
    HealthSnapshot,
    InfraType,
    Severity,
)


class PodHealthAnalyzer(BaseAnalyzer):
    """Detects unhealthy pod conditions.

    Checks for CrashLoopBackOff, OOMKilled, excessive restarts,
    stuck Pending pods, and ImagePullBackOff errors.
    """

    @property
    def name(self) -> str:
        return "pod_health"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.POD_HEALTH

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snapshot in snapshots:
            if snapshot.infra_type != InfraType.KUBERNETES:
                continue
            if "pods" not in snapshot.data:
                continue

            namespace = snapshot.data.get("namespace", "default")
            for pod in snapshot.data["pods"]:
                findings.extend(self._check_pod(pod, namespace))

        return findings

    def _check_pod(self, pod: dict, namespace: str) -> list[Finding]:
        findings: list[Finding] = []
        pod_name = pod["name"]
        phase = pod.get("phase", "Unknown")
        restart_threshold = self.config.get("crashloop_restart_threshold", 5)

        for container in pod.get("containers", []):
            container_name = container["name"]
            restart_count = container.get("restart_count", 0)
            state = container.get("state", {})
            waiting_reason = state.get("waiting_reason")
            terminated_reason = state.get("terminated_reason")
            target = f"k8s://{namespace}/{pod_name}/{container_name}"

            # CrashLoopBackOff
            if waiting_reason == "CrashLoopBackOff":
                findings.append(Finding(
                    finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"CrashLoopBackOff: {pod_name}/{container_name}",
                    description=(
                        f"Container {container_name} in pod {pod_name} (namespace: {namespace}) "
                        f"is in CrashLoopBackOff with {restart_count} restarts. "
                        f"The container keeps crashing and K8s is backing off restart attempts."
                    ),
                    target=target,
                    infra_type=InfraType.KUBERNETES,
                    evidence=[
                        "State: CrashLoopBackOff",
                        f"Restart count: {restart_count}",
                        f"Pod phase: {phase}",
                    ],
                    metrics={"restart_count": restart_count},
                ))

            # OOMKilled
            elif terminated_reason == "OOMKilled":
                findings.append(Finding(
                    finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"OOMKilled: {pod_name}/{container_name}",
                    description=(
                        f"Container {container_name} in pod {pod_name} (namespace: {namespace}) "
                        f"was killed due to out-of-memory. Consider increasing memory limits."
                    ),
                    target=target,
                    infra_type=InfraType.KUBERNETES,
                    evidence=[
                        "Terminated reason: OOMKilled",
                        f"Restart count: {restart_count}",
                    ],
                    metrics={"restart_count": restart_count},
                ))

            # ImagePullBackOff / ErrImagePull
            elif waiting_reason in ("ImagePullBackOff", "ErrImagePull"):
                findings.append(Finding(
                    finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.HIGH,
                    title=f"Image pull failure: {pod_name}/{container_name}",
                    description=(
                        f"Container {container_name} in pod {pod_name} (namespace: {namespace}) "
                        f"cannot pull its image. Check image name, tag, and registry access."
                    ),
                    target=target,
                    infra_type=InfraType.KUBERNETES,
                    evidence=[
                        f"State: {waiting_reason}",
                        f"Image: {container.get('image', 'unknown')}",
                        f"Message: {state.get('waiting_message', 'N/A')}",
                    ],
                ))

            # Excessive restarts (not CrashLoop yet but concerning)
            elif restart_count >= restart_threshold and waiting_reason != "CrashLoopBackOff":
                findings.append(Finding(
                    finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    title=f"Excessive restarts: {pod_name}/{container_name}",
                    description=(
                        f"Container {container_name} in pod {pod_name} (namespace: {namespace}) "
                        f"has restarted {restart_count} times (threshold: {restart_threshold})."
                    ),
                    target=target,
                    infra_type=InfraType.KUBERNETES,
                    evidence=[f"Restart count: {restart_count}"],
                    metrics={"restart_count": restart_count},
                ))

        # Pending pod
        if phase == "Pending":
            pending_timeout = self.config.get("pending_timeout_minutes", 10)
            creation_ts = pod.get("creation_timestamp")
            if creation_ts:
                try:
                    created = datetime.fromisoformat(creation_ts)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    pending_minutes = (now - created).total_seconds() / 60

                    if pending_minutes >= pending_timeout:
                        findings.append(Finding(
                            finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                            category=self.category,
                            severity=Severity.MEDIUM,
                            title=f"Pod stuck Pending: {pod_name}",
                            description=(
                                f"Pod {pod_name} (namespace: {namespace}) has been Pending "
                                f"for {pending_minutes:.0f} minutes "
                                f"(threshold: {pending_timeout} min). "
                                f"Check node resources, taints, and scheduling constraints."
                            ),
                            target=f"k8s://{namespace}/{pod_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                "Phase: Pending",
                                f"Duration: {pending_minutes:.0f} minutes",
                                f"Node: {pod.get('node_name', 'unassigned')}",
                            ],
                            metrics={"pending_minutes": pending_minutes},
                        ))
                except (ValueError, TypeError):
                    pass

        # Failed pod
        if phase == "Failed":
            findings.append(Finding(
                finding_id=f"POD-{uuid.uuid4().hex[:8]}",
                category=self.category,
                severity=Severity.HIGH,
                title=f"Pod Failed: {pod_name}",
                description=(
                    f"Pod {pod_name} (namespace: {namespace}) is in Failed state."
                ),
                target=f"k8s://{namespace}/{pod_name}",
                infra_type=InfraType.KUBERNETES,
                evidence=["Phase: Failed"],
            ))

        return findings
