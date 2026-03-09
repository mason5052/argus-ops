"""SQLite-backed storage for inventory snapshots and asset graphs."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from argus_ops.models import Asset, Capability, InventorySnapshot, Relation

_DEFAULT_DB_PATH = Path.home() / ".argus-ops" / "inventory.db"


class InventoryStore:
    """Persist inventory snapshots and query the latest discovered asset graph."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inventory_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    collector_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inventory_assets (
                    snapshot_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    infra_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inventory_relations (
                    snapshot_id TEXT NOT NULL,
                    source_asset_id TEXT NOT NULL,
                    target_asset_id TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inventory_capabilities (
                    snapshot_id TEXT NOT NULL,
                    capability_name TEXT NOT NULL,
                    collector_name TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def save_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Persist a full inventory snapshot."""
        payload = json.dumps(snapshot.model_dump(mode="json"))
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO inventory_snapshots
                    (snapshot_id, collector_name, timestamp, target, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot.snapshot_id,
                    snapshot.collector_name,
                    snapshot.timestamp.isoformat(),
                    snapshot.target,
                    payload,
                ),
            )
            conn.execute(
                "DELETE FROM inventory_assets WHERE snapshot_id = ?",
                (snapshot.snapshot_id,),
            )
            conn.execute(
                "DELETE FROM inventory_relations WHERE snapshot_id = ?",
                (snapshot.snapshot_id,),
            )
            conn.execute(
                "DELETE FROM inventory_capabilities WHERE snapshot_id = ?",
                (snapshot.snapshot_id,),
            )
            conn.executemany(
                """
                INSERT INTO inventory_assets
                    (snapshot_id, asset_id, asset_type, name, infra_type, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot.snapshot_id,
                        asset.asset_id,
                        asset.asset_type.value,
                        asset.name,
                        asset.infra_type.value,
                        json.dumps(asset.model_dump(mode="json")),
                    )
                    for asset in snapshot.assets
                ],
            )
            conn.executemany(
                """
                INSERT INTO inventory_relations
                    (snapshot_id, source_asset_id, target_asset_id, relation_type, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        snapshot.snapshot_id,
                        relation.source_asset_id,
                        relation.target_asset_id,
                        relation.relation_type,
                        json.dumps(relation.model_dump(mode="json")),
                    )
                    for relation in snapshot.relations
                ],
            )
            conn.executemany(
                """
                INSERT INTO inventory_capabilities
                    (snapshot_id, capability_name, collector_name, payload)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (
                        snapshot.snapshot_id,
                        capability.name,
                        capability.collector_name,
                        json.dumps(capability.model_dump(mode="json")),
                    )
                    for capability in snapshot.capabilities
                ],
            )

    def load_latest_snapshots(self, limit: int = 20) -> list[InventorySnapshot]:
        """Load the most recent inventory snapshots."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT payload
                FROM inventory_snapshots
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [InventorySnapshot.model_validate_json(row[0]) for row in rows]

    def load_inventory_summary(self) -> dict[str, object]:
        """Return an aggregated view of the latest inventory state."""
        snapshots = self.load_latest_snapshots(limit=50)
        asset_map: dict[str, Asset] = {}
        relation_map: dict[tuple[str, str, str], Relation] = {}
        capability_map: dict[str, Capability] = {}

        for snapshot in reversed(snapshots):
            for asset in snapshot.assets:
                asset_map[asset.asset_id] = asset
            for relation in snapshot.relations:
                relation_map[
                    (
                        relation.source_asset_id,
                        relation.target_asset_id,
                        relation.relation_type,
                    )
                ] = relation
            for capability in snapshot.capabilities:
                capability_map[capability.name] = capability

        return {
            "snapshot_count": len(snapshots),
            "latest_snapshot": snapshots[0].timestamp.isoformat() if snapshots else None,
            "assets": [asset.model_dump(mode="json") for asset in asset_map.values()],
            "relations": [relation.model_dump(mode="json") for relation in relation_map.values()],
            "capabilities": [
                capability.model_dump(mode="json")
                for capability in capability_map.values()
            ],
        }
