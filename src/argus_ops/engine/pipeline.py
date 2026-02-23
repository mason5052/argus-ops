"""Core orchestration pipeline: collect -> analyze -> diagnose."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from argus_ops.ai.base import BaseAIProvider
from argus_ops.analyzers.base import BaseAnalyzer
from argus_ops.collectors.base import BaseCollector
from argus_ops.models import Finding, HealthSnapshot, Incident

logger = logging.getLogger("argus_ops.engine")

# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

class CircuitOpen(Exception):
    """Raised when a circuit breaker is open (collector in failure state)."""


class CollectorCircuitBreaker:
    """Simple half-open circuit breaker for a single collector.

    States:
      CLOSED  -- normal operation, calls pass through
      OPEN    -- failure threshold exceeded; calls rejected immediately
      HALF_OPEN -- one trial call allowed after reset_timeout to test recovery

    Args:
        name: Collector name (for logging).
        failure_threshold: Consecutive failures before opening the circuit.
        reset_timeout: Seconds to wait before moving OPEN -> HALF_OPEN.
    """

    _CLOSED = "CLOSED"
    _OPEN = "OPEN"
    _HALF_OPEN = "HALF_OPEN"

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        reset_timeout: float = 60.0,
    ) -> None:
        import time as _time_mod

        self._name = name
        self._failure_threshold = failure_threshold
        self._reset_timeout = reset_timeout
        self._failures = 0
        self._state = self._CLOSED
        self._opened_at: float | None = None
        self._time = _time_mod  # injectable for tests

    @property
    def state(self) -> str:
        return self._state

    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Execute *fn* if circuit allows; raises CircuitOpen otherwise."""
        if self._state == self._OPEN:
            elapsed = self._time.monotonic() - (self._opened_at or 0)
            if elapsed >= self._reset_timeout:
                self._state = self._HALF_OPEN
                logger.info(
                    "Circuit breaker '%s': OPEN -> HALF_OPEN (trial call)", self._name
                )
            else:
                raise CircuitOpen(
                    f"Circuit breaker '{self._name}' is OPEN "
                    f"(reset in {self._reset_timeout - elapsed:.0f}s)"
                )

        try:
            result = fn(*args, **kwargs)
        except Exception:
            self._record_failure()
            raise
        else:
            self._record_success()
            return result

    def _record_failure(self) -> None:
        self._failures += 1
        if self._state == self._HALF_OPEN or self._failures >= self._failure_threshold:
            self._state = self._OPEN
            self._opened_at = self._time.monotonic()
            logger.warning(
                "Circuit breaker '%s': -> OPEN after %d failure(s)", self._name, self._failures
            )

    def _record_success(self) -> None:
        if self._state == self._HALF_OPEN:
            logger.info("Circuit breaker '%s': HALF_OPEN -> CLOSED (recovered)", self._name)
        self._failures = 0
        self._state = self._CLOSED


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class Pipeline:
    """Orchestrates the collect -> analyze -> diagnose workflow.

    Collectors are wrapped with:
      - Exponential backoff retry (tenacity): up to 3 attempts, 2s->4s->8s
      - Circuit breaker: opens after 3 consecutive failures, resets after 60s

    Usage:
        pipeline = Pipeline(collectors, analyzers, ai_provider)
        findings = pipeline.scan()                    # no AI
        incidents = pipeline.diagnose(findings)       # with AI
    """

    # Retry policy: 3 attempts total, exponential back-off 2s -> 4s -> 8s
    _RETRY_ATTEMPTS = 3
    _RETRY_WAIT_MIN = 2      # seconds
    _RETRY_WAIT_MAX = 8      # seconds

    # Circuit breaker policy
    _CB_FAILURE_THRESHOLD = 3
    _CB_RESET_TIMEOUT = 60.0  # seconds

    def __init__(
        self,
        collectors: list[BaseCollector],
        analyzers: list[BaseAnalyzer],
        ai_provider: BaseAIProvider | None = None,
    ):
        self.collectors = collectors
        self.analyzers = analyzers
        self.ai_provider = ai_provider
        # One circuit breaker per collector, keyed by collector name
        self._circuit_breakers: dict[str, CollectorCircuitBreaker] = {}

    def _get_circuit_breaker(self, collector: BaseCollector) -> CollectorCircuitBreaker:
        name = collector.name
        if name not in self._circuit_breakers:
            self._circuit_breakers[name] = CollectorCircuitBreaker(
                name=name,
                failure_threshold=self._CB_FAILURE_THRESHOLD,
                reset_timeout=self._CB_RESET_TIMEOUT,
            )
        return self._circuit_breakers[name]

    def collect(self) -> list[HealthSnapshot]:
        """Run all collectors with retry + circuit-breaker protection."""
        snapshots: list[HealthSnapshot] = []

        for collector in self.collectors:
            logger.info("Running collector: %s", collector.name)
            cb = self._get_circuit_breaker(collector)

            try:
                result = cb.call(self._collect_with_retry, collector)
                snapshots.extend(result)
                logger.info(
                    "Collector %s returned %d snapshot(s)", collector.name, len(result)
                )
            except CircuitOpen as e:
                logger.warning("Collector %s skipped: %s", collector.name, e)
            except RetryError as e:
                logger.error(
                    "Collector %s failed after %d retries: %s",
                    collector.name,
                    self._RETRY_ATTEMPTS,
                    e.last_attempt.exception(),
                )
            except Exception as e:
                logger.error("Collector %s failed: %s", collector.name, e)

        return snapshots

    def _collect_with_retry(self, collector: BaseCollector) -> list[HealthSnapshot]:
        """Run a single collector with exponential backoff retry."""

        @retry(
            retry=retry_if_exception_type(Exception),
            stop=stop_after_attempt(self._RETRY_ATTEMPTS),
            wait=wait_exponential(
                multiplier=1, min=self._RETRY_WAIT_MIN, max=self._RETRY_WAIT_MAX
            ),
            reraise=False,
        )
        def _run() -> list[HealthSnapshot]:
            if not collector.is_available():
                logger.warning("Collector %s is not available, skipping", collector.name)
                return []
            return collector.collect()

        return _run()

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
