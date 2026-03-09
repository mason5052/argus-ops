"""Background watch thread: polls cluster, persists incidents, and refreshes inventory."""

from __future__ import annotations

import logging
import queue
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from argus_ops.discovery import DiscoveryService
from argus_ops.inventory_store import InventoryStore
from argus_ops.models import Finding, Incident
from argus_ops.store import IncidentStore

logger = logging.getLogger("argus_ops.web.watch")

_MAX_TREND = 120
_MAX_EVENT_QUEUE = 500


class DiagnoseStatus(str, Enum):
    """State of the on-demand AI diagnosis operation."""

    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"


class WatchService:
    """Run background scan and discovery loops for the dashboard."""

    def __init__(
        self,
        pipeline_factory: Callable[[], Any],
        interval: int = 30,
        ai_provider: Any | None = None,
        db_path: Any | None = None,
        discovery_service: DiscoveryService | None = None,
        inventory_store: InventoryStore | None = None,
    ) -> None:
        self._factory = pipeline_factory
        self._interval = interval
        self._ai_provider = ai_provider
        self._lock = threading.Lock()
        self._diagnose_lock = threading.Lock()
        self._store = IncidentStore(db_path=db_path) if db_path is not None else IncidentStore()
        self._inventory_store = inventory_store or InventoryStore()
        self._discovery = discovery_service or DiscoveryService([], store=self._inventory_store)

        self._findings: list[Finding] = []
        self._nodes: list[dict[str, Any]] = []
        self._trend: list[dict[str, Any]] = []
        self._inventory_summary: dict[str, Any] = self._inventory_store.load_inventory_summary()
        self._last_scan: datetime | None = None
        self._error: str | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._diagnose_status: DiagnoseStatus = DiagnoseStatus.IDLE
        self._diagnose_error: str | None = None
        self._event_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=_MAX_EVENT_QUEUE)

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="argus-watch")
        self._thread.start()
        logger.info("WatchService started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._running = False

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "findings": list(self._findings),
                "nodes": list(self._nodes),
                "trend": list(self._trend),
                "inventory": dict(self._inventory_summary),
                "last_scan": self._last_scan.isoformat() if self._last_scan else None,
                "error": self._error,
                "interval": self._interval,
                "diagnose_status": self._diagnose_status.value,
                "diagnose_error": self._diagnose_error,
            }

    def get_incidents(self, limit: int = 50, offset: int = 0) -> list[Incident]:
        return self._store.load_incidents(limit=limit, offset=offset)

    def get_inventory_summary(self) -> dict[str, Any]:
        return self._inventory_store.load_inventory_summary()

    def diagnose_now(self) -> list[Incident]:
        from argus_ops.engine.pipeline import Pipeline

        if not self._ai_provider:
            raise RuntimeError(
                "No AI provider configured. Set OPENAI_API_KEY to enable AI diagnosis."
            )
        if not self._diagnose_lock.acquire(blocking=False):
            raise RuntimeError(
                "AI diagnosis is already in progress. Please wait for it to complete."
            )

        with self._lock:
            self._diagnose_status = DiagnoseStatus.RUNNING
            self._diagnose_error = None
            findings = list(self._findings)

        try:
            if not findings:
                with self._lock:
                    self._diagnose_status = DiagnoseStatus.IDLE
                return []
            pipeline = Pipeline(collectors=[], analyzers=[], ai_provider=self._ai_provider)
            incidents = pipeline.diagnose(findings)
            for incident in incidents:
                self._store.save_incident(incident)
            with self._lock:
                self._diagnose_status = DiagnoseStatus.IDLE
            return incidents
        except Exception as exc:
            with self._lock:
                self._diagnose_status = DiagnoseStatus.ERROR
                self._diagnose_error = str(exc)
            raise
        finally:
            self._diagnose_lock.release()

    def set_interval(self, seconds: int) -> None:
        if seconds < 10:
            raise ValueError("Interval must be at least 10 seconds")
        with self._lock:
            self._interval = seconds

    def get_pending_events(self, max_events: int = 50) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while len(events) < max_events:
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def _push_event(self, event_type: str, data: dict[str, Any]) -> None:
        payload = {"type": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), **data}
        try:
            self._event_queue.put_nowait(payload)
        except queue.Full:
            pass

    def _loop(self) -> None:
        while self._running:
            try:
                self._run_scan()
            except Exception as exc:
                logger.error("Scan cycle failed: %s", exc)
                with self._lock:
                    self._error = str(exc)
            with self._lock:
                interval = self._interval
            time.sleep(interval)

    def _run_scan(self) -> None:
        pipeline = self._factory()
        snapshots = pipeline.collect()
        findings = pipeline.analyze(snapshots)

        node_dicts: list[dict[str, Any]] = []
        for snapshot in snapshots:
            if snapshot.data.get("nodes"):
                node_dicts = snapshot.data["nodes"]
                break

        trend_point = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "critical": sum(1 for finding in findings if finding.severity.value == "critical"),
            "high": sum(1 for finding in findings if finding.severity.value == "high"),
            "medium": sum(1 for finding in findings if finding.severity.value == "medium"),
            "low": sum(1 for finding in findings if finding.severity.value == "low"),
            "info": sum(1 for finding in findings if finding.severity.value == "info"),
        }
        self._store.save_trend_point(trend_point)
        self._discovery.discover()
        inventory_summary = self._inventory_store.load_inventory_summary()

        with self._lock:
            self._findings = findings
            self._nodes = node_dicts
            self._inventory_summary = inventory_summary
            self._trend.append(trend_point)
            if len(self._trend) > _MAX_TREND:
                self._trend = self._trend[-_MAX_TREND:]
            self._last_scan = datetime.now(timezone.utc)
            self._error = None

        self._push_event(
            "scan_complete",
            {
                "finding_count": len(findings),
                "node_count": len(node_dicts),
                "asset_count": len(inventory_summary.get("assets", [])),
                "trend_point": trend_point,
            },
        )
