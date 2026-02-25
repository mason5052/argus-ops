"""Cross-layer correlation engine for matching Argus-Ops actions to K8s events."""

from __future__ import annotations

import logging
from datetime import date, timedelta

from argus_ops.audit.logger import AuditLogger
from argus_ops.audit.k8s_audit import K8sAuditCollector
from argus_ops.audit.models import AuditRecord, K8sAuditEvent

logger = logging.getLogger(__name__)

# Time window for correlating events (seconds)
_CORRELATION_WINDOW = 30


class AuditCorrelator:
    """Correlates Layer 1 (Argus-Ops) records with Layer 2 (K8s) events.

    Identifies:
    - K8s changes made through Argus-Ops (matched)
    - K8s changes made externally (drift detection)
    """

    def __init__(
        self,
        audit_logger: AuditLogger,
        k8s_collector: K8sAuditCollector,
    ) -> None:
        self._layer1 = audit_logger
        self._layer2 = k8s_collector

    def get_drift(
        self,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        limit: int = 100,
    ) -> list[K8sAuditEvent]:
        """Return K8s events NOT correlated to any Argus-Ops operation.

        These represent changes made outside Argus-Ops (drift).
        """
        l1_records = self._layer1.query(
            start_date=start_date, end_date=end_date, limit=100_000
        )
        l2_events = self._layer2.query(
            start_date=start_date, end_date=end_date, limit=100_000
        )

        # Build a set of (resource, namespace, approx_time) from Layer 1
        l1_targets: set[tuple[str, str]] = set()
        for rec in l1_records:
            # Extract resource info from target string
            # Format: "kind/name (namespace: ns)"
            target_key = rec.target.lower().strip()
            l1_targets.add((target_key, rec.timestamp.isoformat()[:16]))

        drift: list[K8sAuditEvent] = []
        for ev in l2_events:
            ev_key = f"{ev.resource_kind}/{ev.resource_name} (namespace: {ev.namespace})".lower()
            ev_time = ev.timestamp.isoformat()[:16]
            # Check if any L1 record matches within the correlation window
            matched = False
            for rec in l1_records:
                rec_target = rec.target.lower().strip()
                if ev.resource_name.lower() in rec_target:
                    time_diff = abs(
                        (ev.timestamp - rec.timestamp).total_seconds()
                    )
                    if time_diff <= _CORRELATION_WINDOW:
                        ev.argus_ops_record_id = rec.id
                        matched = True
                        break
            if not matched:
                drift.append(ev)
                if len(drift) >= limit:
                    break

        logger.info(
            "Correlation: %d L1 records, %d L2 events, %d drift events",
            len(l1_records),
            len(l2_events),
            len(drift),
        )
        return drift

    def get_combined(
        self,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        actor: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return a combined timeline from both layers, sorted by timestamp.

        Each entry is a dict with 'layer' (1 or 2), 'timestamp', and the record.
        """
        results: list[dict] = []

        l1_records = self._layer1.query(
            start_date=start_date, end_date=end_date, actor=actor, limit=limit
        )
        for rec in l1_records:
            results.append(
                {
                    "layer": 1,
                    "timestamp": rec.timestamp,
                    "source": "argus-ops",
                    "actor": rec.actor,
                    "action": rec.action,
                    "target": rec.target,
                    "risk_level": rec.risk_level.value,
                    "record": rec,
                }
            )

        l2_events = self._layer2.query(
            start_date=start_date,
            end_date=end_date,
            user=actor,
            limit=limit,
        )
        for ev in l2_events:
            results.append(
                {
                    "layer": 2,
                    "timestamp": ev.timestamp,
                    "source": "k8s-api",
                    "actor": ev.user,
                    "action": ev.verb,
                    "target": f"{ev.resource_kind}/{ev.resource_name}",
                    "risk_level": "",
                    "record": ev,
                }
            )

        results.sort(key=lambda x: x["timestamp"], reverse=True)
        return results[:limit]
