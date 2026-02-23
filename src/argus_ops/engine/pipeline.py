"""Core orchestration pipeline: collect -> analyze -> diagnose."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from argus_ops.ai.base import BaseAIProvider
from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.collectors.base import BaseCollector
from argus_ops.models import Finding, HealthSnapshot, Incident

logger = logging.getLogger("argus_ops.engine")


class Pipeline:
    """Orchestrates the collect -> analyze -> diagnose workflow.

    Usage:
        pipeline = Pipeline(collectors, analyzers, ai_provider)
        findings = pipeline.scan()                    # no AI
        incidents = pipeline.diagnose(findings)       # with AI
    """

    def __init__(
        self,
        collectors: list[BaseCollector],
        analyzers: list[BaseAnalyzer],
        ai_provider: BaseAIProvider | None = None,
    ):
        self.collectors = collectors
        self.analyzers = analyzers
        self.ai_provider = ai_provider

    def collect(self) -> list[HealthSnapshot]:
        """Run all collectors and return health snapshots."""
        snapshots: list[HealthSnapshot] = []

        for collector in self.collectors:
            logger.info("Running collector: %s", collector.name)
            try:
                if not collector.is_available():
                    logger.warning("Collector %s is not available, skipping", collector.name)
                    continue
                result = collector.collect()
                snapshots.extend(result)
                logger.info(
                    "Collector %s returned %d snapshot(s)", collector.name, len(result)
                )
            except Exception as e:
                logger.error("Collector %s failed: %s", collector.name, e)

        return snapshots

    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        """Run all analyzers against snapshots and return findings."""
        findings: list[Finding] = []

        for analyzer in self.analyzers:
            logger.info("Running analyzer: %s", analyzer.name)
            try:
                result = analyzer.analyze(snapshots)
                findings.extend(result)
                if result:
                    logger.info(
                        "Analyzer %s found %d issue(s)", analyzer.name, len(result)
                    )
            except Exception as e:
                logger.error("Analyzer %s failed: %s", analyzer.name, e)

        return findings

    def scan(self) -> list[Finding]:
        """Collect + analyze. Returns findings with no AI."""
        snapshots = self.collect()
        return self.analyze(snapshots)

    def diagnose(
        self,
        findings: list[Finding],
        context: dict[str, Any] | None = None,
    ) -> list[Incident]:
        """Collect + analyze + AI diagnosis. Returns incidents."""
        if not findings:
            return []

        if not self.ai_provider:
            logger.warning("No AI provider configured, returning findings as incidents")
            return [self._findings_to_incident(findings)]

        # Group findings by infra type for targeted diagnosis
        groups = self._group_findings(findings)
        incidents: list[Incident] = []

        for group_name, group_findings in groups.items():
            if not group_findings:
                continue
            logger.info(
                "Diagnosing group '%s' with %d finding(s)", group_name, len(group_findings)
            )
            try:
                diagnosis = self.ai_provider.diagnose(
                    group_findings, context or {}
                )
                incident = Incident(
                    incident_id=f"INC-{uuid.uuid4().hex[:8]}",
                    findings=group_findings,
                    diagnosis=diagnosis,
                )
                incidents.append(incident)
            except Exception as e:
                logger.error("Diagnosis failed for group '%s': %s", group_name, e)
                incidents.append(self._findings_to_incident(group_findings))

        return incidents

    def run_full(
        self, context: dict[str, Any] | None = None
    ) -> list[Incident]:
        """Full pipeline: collect + analyze + diagnose."""
        findings = self.scan()
        if not findings:
            return []
        return self.diagnose(findings, context)

    @staticmethod
    def _group_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by infra_type for targeted AI diagnosis."""
        groups: dict[str, list[Finding]] = {}
        for finding in findings:
            key = finding.infra_type.value
            groups.setdefault(key, []).append(finding)
        return groups

    @staticmethod
    def _findings_to_incident(findings: list[Finding]) -> Incident:
        return Incident(
            incident_id=f"INC-{uuid.uuid4().hex[:8]}",
            findings=findings,
        )
