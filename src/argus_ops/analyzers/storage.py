"""Storage analyzer: orphaned PVs, unbound PVCs, HostPath without PVC."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import Finding, FindingCategory, HealthSnapshot, InfraType, Severity

logger = logging.getLogger(__name__)


class StorageAnalyzer(BaseAnalyzer):
    """Detects storage-related issues in the cluster.

    Checks:
    - Orphaned PersistentVolumes (Released state, no claim)
    - Unbound PersistentVolumeClaims (Pending state)
    - HostPath volumes without PVC backing (data loss risk)
    """

    @property
    def name(self) -> str:
        return "storage"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.STORAGE

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snap in snapshots:
            if snap.collector_name != "kubernetes":
                continue

            data = snap.data

            # Check PersistentVolumes
            pvs = data.get("persistent_volumes", [])
            for pv in pvs:
                pv_name = pv.get("name", "")
                phase = pv.get("phase", "")
                capacity = pv.get("capacity", {}).get("storage", "unknown")

                if phase == "Released":
                    findings.append(
                        Finding(
                            finding_id=f"STOR-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.STORAGE,
                            severity=Severity.MEDIUM,
                            title=f"Orphaned PersistentVolume: {pv_name}",
                            description=(
                                f"PV '{pv_name}' ({capacity}) is in Released state "
                                "with no active claim. This storage is allocated but unused."
                            ),
                            target=f"pv/{pv_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                f"Phase: {phase}",
                                f"Capacity: {capacity}",
                                f"Reclaim policy: {pv.get('reclaim_policy', 'unknown')}",
                            ],
                        )
                    )
                elif phase == "Failed":
                    findings.append(
                        Finding(
                            finding_id=f"STOR-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.STORAGE,
                            severity=Severity.HIGH,
                            title=f"Failed PersistentVolume: {pv_name}",
                            description=f"PV '{pv_name}' is in Failed state.",
                            target=f"pv/{pv_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[f"Phase: {phase}", f"Capacity: {capacity}"],
                        )
                    )

            # Check PersistentVolumeClaims
            pvcs = data.get("persistent_volume_claims", [])
            for pvc in pvcs:
                pvc_name = pvc.get("name", "")
                pvc_ns = pvc.get("namespace", "")
                phase = pvc.get("phase", "")

                if phase == "Pending":
                    findings.append(
                        Finding(
                            finding_id=f"STOR-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.STORAGE,
                            severity=Severity.MEDIUM,
                            title=f"Unbound PVC: {pvc_name}",
                            description=(
                                f"PVC '{pvc_name}' in namespace '{pvc_ns}' is Pending "
                                "-- no matching PV available."
                            ),
                            target=f"{pvc_ns}/pvc/{pvc_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[f"Phase: {phase}", f"Namespace: {pvc_ns}"],
                        )
                    )

            # Check for HostPath volumes without PVC
            pods = data.get("pods", [])
            for pod in pods:
                pod_name = pod.get("name", "")
                pod_ns = pod.get("namespace", "")
                volumes = pod.get("volumes", [])
                for vol in volumes:
                    if vol.get("type") == "HostPath":
                        findings.append(
                            Finding(
                                finding_id=f"STOR-{uuid.uuid4().hex[:8]}",
                                category=FindingCategory.STORAGE,
                                severity=Severity.LOW,
                                title=f"HostPath volume in pod {pod_name}",
                                description=(
                                    f"Pod '{pod_name}' in namespace '{pod_ns}' uses "
                                    f"HostPath volume '{vol.get('name', '')}'. "
                                    "Data will be lost if pod migrates to another node."
                                ),
                                target=f"{pod_ns}/pod/{pod_name}",
                                infra_type=InfraType.KUBERNETES,
                                evidence=[
                                    f"Volume: {vol.get('name', '')}",
                                    f"HostPath: {vol.get('path', '')}",
                                ],
                            )
                        )

        return findings
