"""Background watch thread: polls cluster on an interval, stores state in-memory."""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

from argus_ops.models import Finding, Incident

logger = logging.getLogger("argus_ops.web.watch")

_MAX_INCIDENTS = 50    # max AI diagnosis history entries kept in memory
_MAX_TREND = 120       # max trend data points (120 * 30s = 1 hour window)


class WatchService:
    """Runs a background daemon thread that scans the cluster on a fixed interval.

    Thread safety: all mutable state is protected by self._lock.
    Callers read state via get_state(), which returns a snapshot copy under the lock.

    Args:
        pipeline_factory: Zero-arg callable that returns a fresh Pipeline instance.
            Called on every scan cycle so kubeconfig is re-loaded fresh each time.
        interval: Seconds between scan cycles (default: 30).
        ai_provider: Optional AI provider. If set, runs AI diagnosis on every scan
            cycle and appends resulting Incidents to history. Opt-in -- expensive.
    """

    def __init__(
        self,
        pipeline_factory: Callable[[], Any],
        interval: int = 30,
        ai_provider: Any | None = None,
    ) -> None:
        self._factory = pipeline_factory
        self._interval = interval
        self._ai_provider = ai_provider
        self._lock = threading.Lock()

        # Mutable state -- always write under lock
        self._findings: list[Finding] = []
        self._nodes: list[dict[str, Any]] = []
        self._incidents: deque[Incident] = deque(maxlen=_MAX_INCIDENTS)
        self._trend: deque[dict[str, Any]] = deque(maxlen=_MAX_TREND)
        self._last_scan: datetime | None = None
        self._error: str | None = None
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background polling daemon thread."""
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-watch"
        )
        self._thread.start()
        logger.info("WatchService started (interval=%ds)", self._interval)

    def stop(self) -> None:
        """Signal the background thread to stop on its next iteration."""
        self._running = False

    def get_state(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of current state for API handlers.

        Returns a shallow copy of all state lists/dicts under the lock so
        API handlers never need to hold the lock while serializing responses.
        """
        with self._lock:
            return {
                "findings": list(self._findings),
                "nodes": list(self._nodes),
                "incidents": list(self._incidents),
                "trend": list(self._trend),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "error": self._error,
            }

    # -------------------------------------------------------------------------
    # Private methods
    # -------------------------------------------------------------------------

    def _loop(self) -> None:
        """Main polling loop -- runs in the daemon thread."""
        while self._running:
            try:
                self._run_scan()
            except Exception as e:
                logger.error("Scan cycle failed: %s", e)
                with self._lock:
                    self._error = str(e)
            time.sleep(self._interval)

    def _run_scan(self) -> None:
        """Run one full scan cycle: collect -> analyze -> (optionally) diagnose."""
        from argus_ops.engine.pipeline import Pipeline

        pipeline = self._factory()

        # Collect raw snapshots -- needed separately for node grid data
        snapshots = pipeline.collect()

        # Extract node list from the first snapshot that contains "nodes"
        node_dicts: list[dict[str, Any]] = []
        for snap in snapshots:
            if "nodes" in snap.data:
                node_dicts = snap.data["nodes"]
                break

        # Run analyzers against collected snapshots
        findings = pipeline.analyze(snapshots)

        # Build trend point (severity counts at this moment)
        trend_point: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
            "info": sum(1 for f in findings if f.severity.value == "info"),
        }

        # Optional AI diagnosis (opt-in, expensive)
        new_incidents: list[Incident] = []
        if self._ai_provider and findings:
            try:
                ai_pipeline = Pipeline(
                    collectors=[],
                    analyzers=[],
                    ai_provider=self._ai_provider,
                )
                new_incidents = ai_pipeline.diagnose(findings)
            except Exception as e:
                logger.warning("AI diagnosis failed in watch cycle: %s", e)

        with self._lock:
            self._findings = findings
            self._nodes = node_dicts
            self._trend.append(trend_point)
            for inc in new_incidents:
                self._incidents.append(inc)
            self._last_scan = datetime.now(timezone.utc)
            self._error = None

        logger.info(
            "Scan complete: %d finding(s), %d node(s)", len(findings), len(node_dicts)
        )
