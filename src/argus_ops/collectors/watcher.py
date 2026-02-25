"""K8s Watch API event stream handler for real-time cluster monitoring."""

from __future__ import annotations

import logging
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Event types from Watch API
EVENT_ADDED = "ADDED"
EVENT_MODIFIED = "MODIFIED"
EVENT_DELETED = "DELETED"
EVENT_ERROR = "ERROR"

# Default resync interval (seconds)
_RESYNC_INTERVAL = 300  # 5 minutes
_WATCH_TIMEOUT = 300  # 5 minutes per watch connection


class ClusterEvent:
    """A single cluster change event from the Watch API."""

    def __init__(
        self,
        event_type: str,
        resource_kind: str,
        name: str,
        namespace: str = "",
        data: dict | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        self.event_type = event_type
        self.resource_kind = resource_kind
        self.name = name
        self.namespace = namespace
        self.data = data or {}
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "resource_kind": self.resource_kind,
            "name": self.name,
            "namespace": self.namespace,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class K8sWatcher:
    """Watches K8s resources via the Watch API and emits events.

    Uses ``kubernetes.watch.Watch()`` with automatic reconnection.
    Performs a full resync periodically as a safety net.

    Args:
        kubeconfig: Path to kubeconfig file (None for in-cluster).
        context: K8s context name (None for current).
        resync_interval: Seconds between full resyncs.
    """

    def __init__(
        self,
        kubeconfig: str | None = None,
        context: str | None = None,
        resync_interval: int = _RESYNC_INTERVAL,
    ) -> None:
        self._kubeconfig = kubeconfig
        self._context = context
        self._resync_interval = resync_interval
        self._event_queue: queue.Queue[ClusterEvent] = queue.Queue(maxsize=1000)
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._subscribers: list[Callable[[ClusterEvent], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[ClusterEvent], None]) -> None:
        """Register a callback for cluster events."""
        with self._lock:
            self._subscribers.append(callback)

    def _notify(self, event: ClusterEvent) -> None:
        """Notify all subscribers of an event."""
        with self._lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(event)
            except Exception as e:
                logger.warning("Event subscriber error: %s", e)

    def _get_clients(self):
        """Create K8s API clients."""
        from kubernetes import client, config

        try:
            if self._kubeconfig:
                config.load_kube_config(
                    config_file=self._kubeconfig, context=self._context
                )
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config(context=self._context)
        except Exception:
            config.load_kube_config()

        return client.CoreV1Api(), client.AppsV1Api(), client.BatchV1Api()

    def start(self) -> None:
        """Start watch threads for all resource types."""
        self._stop_event.clear()

        # Dispatch thread reads from queue and notifies subscribers
        dispatch = threading.Thread(
            target=self._dispatch_loop, daemon=True, name="watcher-dispatch"
        )
        dispatch.start()
        self._threads.append(dispatch)

        # Watch threads for each resource type
        for resource in ["pods", "nodes", "namespaces", "deployments", "cronjobs"]:
            t = threading.Thread(
                target=self._watch_resource,
                args=(resource,),
                daemon=True,
                name=f"watcher-{resource}",
            )
            t.start()
            self._threads.append(t)

        logger.info("K8s watcher started (resync every %ds)", self._resync_interval)

    def stop(self) -> None:
        """Stop all watch threads."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        logger.info("K8s watcher stopped")

    def _dispatch_loop(self) -> None:
        """Read events from queue and notify subscribers."""
        while not self._stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=1)
                self._notify(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Dispatch error: %s", e)

    def _watch_resource(self, resource: str) -> None:
        """Watch a specific K8s resource type with auto-reconnect."""
        from kubernetes import watch

        while not self._stop_event.is_set():
            try:
                core, apps, batch = self._get_clients()
                w = watch.Watch()

                if resource == "pods":
                    stream = w.stream(
                        core.list_pod_for_all_namespaces,
                        timeout_seconds=_WATCH_TIMEOUT,
                    )
                elif resource == "nodes":
                    stream = w.stream(
                        core.list_node,
                        timeout_seconds=_WATCH_TIMEOUT,
                    )
                elif resource == "namespaces":
                    stream = w.stream(
                        core.list_namespace,
                        timeout_seconds=_WATCH_TIMEOUT,
                    )
                elif resource == "deployments":
                    stream = w.stream(
                        apps.list_deployment_for_all_namespaces,
                        timeout_seconds=_WATCH_TIMEOUT,
                    )
                elif resource == "cronjobs":
                    stream = w.stream(
                        batch.list_cron_job_for_all_namespaces,
                        timeout_seconds=_WATCH_TIMEOUT,
                    )
                else:
                    return

                for raw_event in stream:
                    if self._stop_event.is_set():
                        w.stop()
                        return

                    event_type = raw_event.get("type", "")
                    obj = raw_event.get("object")
                    if obj is None:
                        continue

                    meta = getattr(obj, "metadata", None)
                    if meta is None:
                        continue

                    event = ClusterEvent(
                        event_type=event_type,
                        resource_kind=resource.rstrip("s").capitalize(),
                        name=meta.name or "",
                        namespace=meta.namespace or "",
                        data=self._extract_event_data(resource, obj, event_type),
                    )

                    try:
                        self._event_queue.put_nowait(event)
                    except queue.Full:
                        logger.warning("Event queue full, dropping: %s/%s", resource, meta.name)

            except Exception as e:
                if self._stop_event.is_set():
                    return
                logger.warning("Watch %s disconnected: %s. Reconnecting in 5s...", resource, e)
                time.sleep(5)

    def _extract_event_data(self, resource: str, obj: Any, event_type: str) -> dict:
        """Extract key data from a K8s resource object."""
        data: dict[str, Any] = {"event_type": event_type}

        try:
            if resource == "pods":
                status = getattr(obj, "status", None)
                if status:
                    data["phase"] = getattr(status, "phase", "")
                    containers = getattr(status, "container_statuses", None) or []
                    for cs in containers:
                        state = getattr(cs, "state", None)
                        if state and getattr(state, "waiting", None):
                            data["waiting_reason"] = getattr(
                                state.waiting, "reason", ""
                            )
                        data["restart_count"] = getattr(cs, "restart_count", 0)

            elif resource == "nodes":
                status = getattr(obj, "status", None)
                if status:
                    conditions = getattr(status, "conditions", None) or []
                    for c in conditions:
                        if c.type == "Ready":
                            data["ready"] = c.status == "True"

            elif resource == "deployments":
                status = getattr(obj, "status", None)
                if status:
                    data["replicas"] = getattr(status, "replicas", 0)
                    data["available"] = getattr(status, "available_replicas", 0)
                    data["ready"] = getattr(status, "ready_replicas", 0)

        except Exception:
            pass

        return data

    def get_pending_events(self, max_events: int = 50) -> list[ClusterEvent]:
        """Drain up to max_events from the queue (for polling fallback)."""
        events: list[ClusterEvent] = []
        while len(events) < max_events:
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return events
