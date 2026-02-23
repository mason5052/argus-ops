"""Background watch thread: polls cluster on an interval, persists state to SQLite."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from argus_ops.models import Finding, Incident
from argus_ops.store import IncidentStore

logger = logging.getLogger("argus_ops.web.watch")

_MAX_TREND = 120       # max trend data points kept in memory (120 * 30s = 1 hour)


class DiagnoseStatus(str, Enum):
    """State of the on-demand AI diagnosis operation."""

    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"


class WatchService:
    """Runs a background daemon thread that scans the cluster on a fixed interval.

    Thread safety: all mutable state is protected by self._lock.
    Callers read state via get_state(), which returns a snapshot copy under the lock.

    Incident history is persisted to SQLite via IncidentStore so it survives
    process restarts.  The in-memory deque is replaced by a SQLite-backed store.

    Args:
        pipeline_factory: Zero-arg callable that returns a fresh Pipeline instance.
            Called on every scan cycle so kubeconfig is re-loaded fresh each time.
        interval: Seconds between scan cycles (default: 30).
        ai_provider: Optional AI provider used only when diagnose_now() is called
            explicitly. AI diagnosis never runs automatically -- always on demand.
        db_path: Path to the SQLite database file. Pass ":memory:" for in-process
            tests.  Defaults to ~/.argus-ops/history.db (via IncidentStore default).
    """

    def __init__(
        self,
        pipeline_factory: Callable[[], Any],
        interval: int = 30,
        ai_provider: Any | None = None,
        db_path: Any | None = None,
    ) -> None:
        self._factory = pipeline_factory
        self._interval = interval
        self._ai_provider = ai_provider
        self._lock = threading.Lock()
        self._diagnose_lock = threading.Lock()  # prevents concurrent diagnose_now() calls

        # SQLite-backed incident persistence
        self._store = IncidentStore(db_path=db_path) if db_path is not None else IncidentStore()

        # Mutable state -- always write under lock
        self._findings: list[Finding] = []
        self._nodes: list[dict[str, Any]] = []
        self._trend: list[dict[str, Any]] = []
        self._last_scan: datetime | None = None
        self._error: str | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._diagnose_status: DiagnoseStatus = DiagnoseStatus.IDLE
        self._diagnose_error: str | None = None

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
                "trend": list(self._trend),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "error": self._error,
                "interval": self._interval,
                "diagnose_status": self._diagnose_status.value,
                "diagnose_error": self._diagnose_error,
            }

    def get_incidents(self, limit: int = 50, offset: int = 0) -> list[Incident]:
        """Return persisted incident history from SQLite, most recent first."""
        return self._store.load_incidents(limit=limit, offset=offset)

    def diagnose_now(self) -> list[Incident]:
        """Run AI diagnosis on the current findings immediately (on demand).

        Blocks until the AI response is received. Only one call runs at a time;
        concurrent callers receive a RuntimeError explaining that diagnosis is
        already in progress (previously returned an empty list silently).

        Raises:
            RuntimeError: If no AI provider was configured, or if a diagnosis
                is already in progress.
        """
        from argus_ops.engine.pipeline import Pipeline

        if not self._ai_provider:
            raise RuntimeError(
                "No AI provider configured. Set OPENAI_API_KEY and ai_diagnosis in config."
            )

        if not self._diagnose_lock.acquire(blocking=False):
            raise RuntimeError(
                "AI diagnosis is already in progress. Please wait for it to complete."
            )

        with self._lock:
            self._diagnose_status = DiagnoseStatus.RUNNING
            self._diagnose_error = None

        try:
            with self._lock:
                findings = list(self._findings)

            if not findings:
                with self._lock:
                    self._diagnose_status = DiagnoseStatus.IDLE
                return []

            ai_pipeline = Pipeline(collectors=[], analyzers=[], ai_provider=self._ai_provider)
            new_incidents = ai_pipeline.diagnose(findings)

            for inc in new_incidents:
                self._store.save_incident(inc)

            with self._lock:
                self._diagnose_status = DiagnoseStatus.IDLE

            logger.info("diagnose_now() complete: %d incident(s)", len(new_incidents))
            return new_incidents
        except Exception as exc:
            with self._lock:
                self._diagnose_status = DiagnoseStatus.ERROR
                self._diagnose_error = str(exc)
            logger.error("diagnose_now() failed: %s", exc)
            raise
        finally:
            self._diagnose_lock.release()

    def set_interval(self, seconds: int) -> None:
        """Update the watch interval at runtime. Takes effect on the next sleep cycle."""
        if seconds < 10:
            raise ValueError("Interval must be at least 10 seconds")
        with self._lock:
            self._interval = seconds
        logger.info("WatchService interval updated to %ds", seconds)

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
            with self._lock:
                interval = self._interval
            time.sleep(interval)

    def _run_scan(self) -> None:
        """Run one full scan cycle: collect -> analyze."""
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

        # Persist trend point to SQLite for long-term history
        self._store.save_trend_point(trend_point)

        with self._lock:
            self._findings = findings
            self._nodes = node_dicts
            # Keep recent trend in memory for the dashboard chart
            self._trend.append(trend_point)
            if len(self._trend) > _MAX_TREND:
                self._trend = self._trend[-_MAX_TREND:]
            self._last_scan = datetime.now(timezone.utc)
            self._error = None

        logger.info(
            "Scan complete: %d finding(s), %d node(s)", len(findings), len(node_dicts)
        )
