"""SQLite-backed persistence for incident and finding history.

Provides a lightweight, zero-dependency (stdlib only) store so incident
history survives process restarts without requiring an external database.

Schema
------
incidents table:
    id          TEXT PRIMARY KEY  -- INC-xxxxxxxx
    created_at  TEXT              -- ISO-8601 UTC
    status      TEXT              -- open / closed
    max_severity TEXT             -- critical / high / ...
    finding_count INT
    payload     TEXT              -- full Incident JSON (Pydantic model_dump)

trend table:
    id          INTEGER PRIMARY KEY AUTOINCREMENT
    ts          TEXT              -- ISO-8601 UTC
    critical    INT
    high        INT
    medium      INT
    low         INT
    info        INT
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

from argus_ops.models import Diagnosis, Finding, FindingCategory, Incident, InfraType, Severity

logger = logging.getLogger("argus_ops.store")

_DEFAULT_DB_PATH = Path.home() / ".argus-ops" / "history.db"
_MAX_TREND_ROWS = 2880  # 2880 * 30s = 24-hour window at 30s interval


class IncidentStore:
    """Thread-safe SQLite store for incident history and trend data.

    Args:
        db_path: Path to the SQLite database file. Created on first use.
            Defaults to ~/.argus-ops/history.db.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path == ":memory:":
            # SQLite in-memory database for testing.
            # Use a single persistent connection since :memory: creates a new
            # empty DB on each connect() call.
            self._db_path_str = ":memory:"
            self._db_path = Path(":memory:")
            self._memory_conn: sqlite3.Connection | None = sqlite3.connect(
                ":memory:", check_same_thread=False
            )
        else:
            self._db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH
            self._db_path_str = str(self._db_path)
            self._memory_conn = None
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        logger.info("IncidentStore initialised at %s", self._db_path_str)

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def save_incident(self, incident: Incident) -> None:
        """Persist a new incident. Existing incidents with same id are replaced."""
        payload = json.dumps(incident.model_dump(mode="json"))
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO incidents
                    (id, created_at, status, max_severity, finding_count, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.incident_id,
                    incident.created_at.isoformat(),
                    incident.status,
                    incident.max_severity.value,
                    len(incident.findings),
                    payload,
                ),
            )

    def load_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
    ) -> list[Incident]:
        """Load incidents from the store, most recent first.

        Args:
            limit: Maximum number of incidents to return.
            offset: Number of rows to skip (for pagination).
            severity: If set, filter to incidents whose max_severity matches.
        """
        query = "SELECT payload FROM incidents"
        params: list[Any] = []
        if severity:
            query += " WHERE max_severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for (payload,) in rows:
            try:
                result.append(self._incident_from_payload(payload))
            except Exception as exc:
                logger.warning("Skipping corrupt incident row: %s", exc)
        return result

    def count_incidents(self, severity: str | None = None) -> int:
        """Return total number of stored incidents."""
        query = "SELECT COUNT(*) FROM incidents"
        params: list[Any] = []
        if severity:
            query += " WHERE max_severity = ?"
            params.append(severity)
        with self._conn() as conn:
            return conn.execute(query, params).fetchone()[0]

    def save_trend_point(self, point: dict[str, Any]) -> None:
        """Append a trend data point and evict old rows beyond the window."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO trend (ts, critical, high, medium, low, info)
                VALUES (:ts, :critical, :high, :medium, :low, :info)
                """,
                {
                    "ts": point.get("ts"),
                    "critical": point.get("critical", 0),
                    "high": point.get("high", 0),
                    "medium": point.get("medium", 0),
                    "low": point.get("low", 0),
                    "info": point.get("info", 0),
                },
            )
            # Keep only the most recent _MAX_TREND_ROWS rows
            conn.execute(
                """
                DELETE FROM trend WHERE id NOT IN (
                    SELECT id FROM trend ORDER BY id DESC LIMIT ?
                )
                """,
                (_MAX_TREND_ROWS,),
            )

    def load_trend(self, limit: int = 120) -> list[dict[str, Any]]:
        """Return the most recent *limit* trend points, oldest first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT ts, critical, high, medium, low, info
                FROM (SELECT * FROM trend ORDER BY id DESC LIMIT ?)
                ORDER BY id ASC
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "ts": row[0],
                "critical": row[1],
                "high": row[2],
                "medium": row[3],
                "low": row[4],
                "info": row[5],
            }
            for row in rows
        ]

    def clear(self) -> None:
        """Delete all stored incidents and trend points (useful in tests)."""
        with self._conn() as conn:
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM trend")

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id            TEXT PRIMARY KEY,
                    created_at    TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'open',
                    max_severity  TEXT NOT NULL DEFAULT 'info',
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    payload       TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS trend (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts       TEXT NOT NULL,
                    critical INTEGER NOT NULL DEFAULT 0,
                    high     INTEGER NOT NULL DEFAULT 0,
                    medium   INTEGER NOT NULL DEFAULT 0,
                    low      INTEGER NOT NULL DEFAULT 0,
                    info     INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC)"
            )

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a thread-safe auto-committing connection.

        For in-memory databases (used in tests) a single persistent connection
        is reused so the schema and data survive across multiple calls.
        """
        if self._memory_conn is not None:
            # In-memory: use the shared persistent connection
            conn = self._memory_conn
            conn.execute("PRAGMA journal_mode=MEMORY")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        else:
            conn = sqlite3.connect(self._db_path_str, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # concurrent reads while writing
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    @staticmethod
    def _incident_from_payload(payload: str) -> Incident:
        """Reconstruct an Incident from its stored JSON payload."""
        data = json.loads(payload)

        findings = [
            Finding(
                finding_id=f["finding_id"],
                category=FindingCategory(f["category"]),
                severity=Severity(f["severity"]),
                title=f["title"],
                description=f["description"],
                target=f["target"],
                infra_type=InfraType(f["infra_type"]),
                evidence=f.get("evidence", []),
                metrics=f.get("metrics", {}),
                raw_data=f.get("raw_data"),
            )
            for f in data.get("findings", [])
        ]

        diagnosis = None
        if data.get("diagnosis"):
            d = data["diagnosis"]
            diagnosis = Diagnosis(
                diagnosis_id=d["diagnosis_id"],
                finding_ids=d.get("finding_ids", []),
                root_cause=d.get("root_cause", ""),
                explanation=d.get("explanation", ""),
                confidence=d.get("confidence", 0.5),
                recommendations=d.get("recommendations", []),
                related_resources=d.get("related_resources", []),
                model_used=d.get("model_used"),
                tokens_used=d.get("tokens_used"),
                cost_usd=d.get("cost_usd"),
            )

        return Incident(
            incident_id=data["incident_id"],
            findings=findings,
            diagnosis=diagnosis,
            status=data.get("status", "open"),
        )
