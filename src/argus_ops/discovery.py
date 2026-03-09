"""Discovery service for building an inventory graph from collectors."""

from __future__ import annotations

import logging
from typing import Iterable

from argus_ops.collectors.base import BaseCollector
from argus_ops.inventory_store import InventoryStore
from argus_ops.models import InventorySnapshot

logger = logging.getLogger("argus_ops.discovery")


class DiscoveryService:
    """Run discovery collectors and persist their inventory snapshots."""

    def __init__(
        self,
        collectors: Iterable[BaseCollector],
        store: InventoryStore | None = None,
    ) -> None:
        self._collectors = list(collectors)
        self._store = store or InventoryStore()

    def discover(self) -> list[InventorySnapshot]:
        """Run all available discovery collectors and persist their snapshots."""
        snapshots: list[InventorySnapshot] = []
        for collector in self._collectors:
            if not collector.is_available():
                continue
            try:
                snapshot = collector.discover()
            except Exception as exc:
                logger.warning("Discovery failed for %s: %s", collector.name, exc)
                continue
            if snapshot is None:
                continue
            self._store.save_snapshot(snapshot)
            snapshots.append(snapshot)
        return snapshots

    @property
    def store(self) -> InventoryStore:
        """Return the underlying inventory store."""
        return self._store
