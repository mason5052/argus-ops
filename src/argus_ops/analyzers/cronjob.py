"""CronJob analyzer: failed jobs, schedule conflicts, missing history."""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from typing import Any

from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.models import Finding, FindingCategory, HealthSnapshot, InfraType, Severity

logger = logging.getLogger(__name__)


class CronJobAnalyzer(BaseAnalyzer):
    """Detects CronJob-related issues.

    Checks:
    - Failed job pods (Error/CrashLoopBackOff from CronJob owners)
    - Schedule conflicts (multiple CronJobs at same time)
    - Missing history limit (failedJobsHistoryLimit=0)
    - Suspended CronJobs (informational)
    """

    @property
    def name(self) -> str:
        return "cronjob"

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.CRONJOB

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        findings: list[Finding] = []

        for snap in snapshots:
            if snap.collector_name != "kubernetes":
                continue

            data = snap.data
            cronjobs = data.get("cronjobs", [])
            pods = data.get("pods", [])

            # Track schedules per namespace for conflict detection
            schedule_map: dict[str, list[str]] = {}  # "ns:schedule" -> [names]

            for cj in cronjobs:
                cj_name = cj.get("name", "")
                cj_ns = cj.get("namespace", "")
                schedule = cj.get("schedule", "")
                suspended = cj.get("suspended", False)
                failed_limit = cj.get("failed_jobs_history_limit")
                active_jobs = cj.get("active_jobs", 0)

                # Schedule conflict tracking
                key = f"{cj_ns}:{schedule}"
                schedule_map.setdefault(key, []).append(cj_name)

                # Missing history limit
                if failed_limit is not None and failed_limit == 0:
                    findings.append(
                        Finding(
                            finding_id=f"CRON-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.CRONJOB,
                            severity=Severity.LOW,
                            title=f"No failed job history: {cj_name}",
                            description=(
                                f"CronJob '{cj_name}' in namespace '{cj_ns}' has "
                                "failedJobsHistoryLimit=0. Failed job logs are not retained."
                            ),
                            target=f"{cj_ns}/cronjob/{cj_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                f"Schedule: {schedule}",
                                "failedJobsHistoryLimit: 0",
                            ],
                        )
                    )

                # Suspended CronJobs
                if suspended:
                    findings.append(
                        Finding(
                            finding_id=f"CRON-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.CRONJOB,
                            severity=Severity.INFO,
                            title=f"Suspended CronJob: {cj_name}",
                            description=(
                                f"CronJob '{cj_name}' in namespace '{cj_ns}' is suspended."
                            ),
                            target=f"{cj_ns}/cronjob/{cj_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[f"Schedule: {schedule}", "Suspended: True"],
                        )
                    )

            # Schedule conflicts (3+ CronJobs at same time in same namespace)
            for key, names in schedule_map.items():
                if len(names) >= 3:
                    ns, sched = key.split(":", 1)
                    findings.append(
                        Finding(
                            finding_id=f"CRON-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.CRONJOB,
                            severity=Severity.MEDIUM,
                            title=f"Schedule conflict: {len(names)} CronJobs at '{sched}'",
                            description=(
                                f"{len(names)} CronJobs in namespace '{ns}' are scheduled "
                                f"at '{sched}'. Simultaneous execution may cause resource "
                                "contention."
                            ),
                            target=f"{ns}/cronjobs",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                f"Schedule: {sched}",
                                f"CronJobs: {', '.join(names)}",
                            ],
                        )
                    )

            # Failed job pods
            for pod in pods:
                pod_name = pod.get("name", "")
                pod_ns = pod.get("namespace", "")
                phase = pod.get("phase", "")
                owner_kind = pod.get("owner_kind", "")

                if owner_kind == "Job" and phase in ("Failed", "Error"):
                    findings.append(
                        Finding(
                            finding_id=f"CRON-{uuid.uuid4().hex[:8]}",
                            category=FindingCategory.CRONJOB,
                            severity=Severity.HIGH,
                            title=f"Failed job pod: {pod_name}",
                            description=(
                                f"Job pod '{pod_name}' in namespace '{pod_ns}' is in "
                                f"{phase} state."
                            ),
                            target=f"{pod_ns}/pod/{pod_name}",
                            infra_type=InfraType.KUBERNETES,
                            evidence=[
                                f"Phase: {phase}",
                                f"Owner: {owner_kind}",
                            ],
                        )
                    )

        return findings
