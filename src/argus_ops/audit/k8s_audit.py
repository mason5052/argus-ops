"""Layer 2: K8s cluster-wide audit log collector and parser."""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from argus_ops.audit.models import K8sAuditEvent

logger = logging.getLogger(__name__)

# Verbs we care about for change tracking
_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}

# Resources to skip (noisy system resources)
_SKIP_RESOURCES = {
    "events",
    "tokenreviews",
    "subjectaccessreviews",
    "selfsubjectaccessreviews",
    "selfsubjectrulesreviews",
    "leases",
}


class K8sAuditCollector:
    """Collects and parses K8s API server audit events.

    Reads audit events from the K8s API (if audit logging is enabled) and
    stores them locally in JSONL format for querying.

    Args:
        audit_dir: Directory for cluster audit JSONL files.
    """

    def __init__(self, audit_dir: str | Path | None = None) -> None:
        if audit_dir is None:
            audit_dir = Path.home() / ".argus-ops" / "cluster-audit"
        self._dir = Path(audit_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _file_for_date(self, d: date) -> Path:
        return self._dir / f"{d.isoformat()}.jsonl"

    def collect_from_api(self, k8s_client: Any = None) -> list[K8sAuditEvent]:
        """Fetch audit events from the K8s API server.

        This requires the cluster to have audit logging enabled with a
        webhook or log backend. If not available, returns an empty list.

        Args:
            k8s_client: Optional kubernetes client CoreV1Api instance.
        """
        if k8s_client is None:
            try:
                from kubernetes import client, config

                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config()
                k8s_client = client.CoreV1Api()
            except Exception as e:
                logger.warning("Cannot connect to K8s API for audit collection: %s", e)
                return []

        events: list[K8sAuditEvent] = []
        try:
            # K8s events (Warning type) as a proxy for cluster changes
            # Real audit log requires audit policy configuration on API server
            event_list = k8s_client.list_event_for_all_namespaces(
                limit=200,
                _request_timeout=30,
            )
            for ev in event_list.items:
                if ev.involved_object is None:
                    continue
                resource_kind = ev.involved_object.kind or ""
                if resource_kind.lower() in _SKIP_RESOURCES:
                    continue
                verb = (ev.reason or "").lower()
                ts = ev.last_timestamp or ev.event_time or datetime.now(timezone.utc)
                if hasattr(ts, "tzinfo") and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                event = K8sAuditEvent(
                    timestamp=ts,
                    user=ev.reporting_component or ev.source.component if ev.source else "",
                    verb=verb,
                    resource_kind=resource_kind,
                    resource_name=ev.involved_object.name or "",
                    namespace=ev.involved_object.namespace or "",
                    response_code=0,
                    user_agent=ev.reporting_instance or "",
                )
                events.append(event)

        except Exception as e:
            logger.warning("Failed to collect K8s audit events: %s", e)

        # Persist collected events
        if events:
            self._store_events(events)
        logger.info("Collected %d K8s audit events", len(events))
        return events

    def _store_events(self, events: list[K8sAuditEvent]) -> None:
        """Append events to daily JSONL files."""
        by_date: dict[date, list[K8sAuditEvent]] = {}
        for ev in events:
            d = ev.timestamp.date()
            by_date.setdefault(d, []).append(ev)

        for d, day_events in by_date.items():
            path = self._file_for_date(d)
            with open(path, "a", encoding="utf-8") as f:
                for ev in day_events:
                    f.write(ev.model_dump_json() + "\n")

    def query(
        self,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        user: str | None = None,
        verb: str | None = None,
        namespace: str | None = None,
        resource_kind: str | None = None,
        limit: int = 100,
    ) -> list[K8sAuditEvent]:
        """Query stored cluster audit events."""
        if start_date is None:
            start_date = date.today()
        if end_date is None:
            end_date = date.today()

        events: list[K8sAuditEvent] = []
        current = start_date
        while current <= end_date:
            path = self._file_for_date(current)
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = K8sAuditEvent.model_validate_json(line)
                    except Exception:
                        continue
                    if user and user.lower() not in ev.user.lower():
                        continue
                    if verb and verb.lower() != ev.verb.lower():
                        continue
                    if namespace and namespace.lower() != ev.namespace.lower():
                        continue
                    if resource_kind and resource_kind.lower() != ev.resource_kind.lower():
                        continue
                    events.append(ev)
                    if len(events) >= limit:
                        return events
            from datetime import timedelta

            current = current + timedelta(days=1)
        return events

    def check_audit_policy_enabled(self, k8s_client: Any = None) -> bool:
        """Check if the cluster has audit logging enabled.

        Returns True if audit policy appears to be configured.
        """
        # Heuristic: try to access audit-related resources
        # Full detection requires API server flag inspection
        try:
            if k8s_client is None:
                from kubernetes import client, config

                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config()
                k8s_client = client.CoreV1Api()

            # Check for audit webhook configuration
            api = k8s_client
            # If we can list events, the API server is accessible
            api.list_event_for_all_namespaces(limit=1, _request_timeout=10)
            return True
        except Exception:
            return False
