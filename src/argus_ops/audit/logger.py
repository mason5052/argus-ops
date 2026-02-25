"""Layer 1: Argus-Ops operation JSONL logger with daily rotation."""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from argus_ops.audit.models import AuditRecord, RiskLevel

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSONL logger for Argus-Ops write operations.

    Storage layout::

        ~/.argus-ops/audit/2026-02-25.jsonl
        ~/.argus-ops/audit/2026-02-26.jsonl

    Args:
        audit_dir: Directory for audit JSONL files.
    """

    def __init__(self, audit_dir: str | Path | None = None) -> None:
        if audit_dir is None:
            audit_dir = Path.home() / ".argus-ops" / "audit"
        self._dir = Path(audit_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _file_for_date(self, d: date) -> Path:
        return self._dir / f"{d.isoformat()}.jsonl"

    def log(self, record: AuditRecord) -> None:
        """Append an audit record to today's log file."""
        path = self._file_for_date(record.timestamp.date())
        with open(path, "a", encoding="utf-8") as f:
            f.write(record.model_dump_json() + "\n")
        logger.debug("Audit record logged: %s -> %s", record.action, record.target)

    def query(
        self,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        actor: str | None = None,
        action: str | None = None,
        risk_level: RiskLevel | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[AuditRecord]:
        """Query audit records with optional filters.

        Args:
            start_date: Earliest date to include (inclusive).
            end_date: Latest date to include (inclusive).
            actor: Filter by actor username (substring match).
            action: Filter by action type (substring match).
            risk_level: Filter by minimum risk level.
            source: Filter by source (heal, chat, auto).
            limit: Maximum records to return.
        """
        if start_date is None:
            start_date = date.today()
        if end_date is None:
            end_date = date.today()

        records: list[AuditRecord] = []
        current = start_date
        while current <= end_date:
            path = self._file_for_date(current)
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = AuditRecord.model_validate_json(line)
                    except Exception:
                        continue
                    if actor and actor.lower() not in rec.actor.lower():
                        continue
                    if action and action.lower() not in rec.action.lower():
                        continue
                    if risk_level and rec.risk_level < risk_level:
                        continue
                    if source and rec.source != source:
                        continue
                    records.append(rec)
                    if len(records) >= limit:
                        return records
            # next day
            from datetime import timedelta

            current = current + timedelta(days=1)
        return records

    def export_csv(
        self,
        output_path: str | Path,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> int:
        """Export audit records to CSV for compliance review.

        Returns:
            Number of records exported.
        """
        import csv

        records = self.query(start_date=start_date, end_date=end_date, limit=100_000)
        fields = [
            "id",
            "timestamp",
            "actor",
            "source",
            "action",
            "target",
            "reason",
            "risk_level",
            "command",
            "dry_run",
            "result_status",
            "rollback_command",
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for rec in records:
                writer.writerow(
                    {
                        "id": rec.id,
                        "timestamp": rec.timestamp.isoformat(),
                        "actor": rec.actor,
                        "source": rec.source,
                        "action": rec.action,
                        "target": rec.target,
                        "reason": rec.reason,
                        "risk_level": rec.risk_level.value,
                        "command": rec.command,
                        "dry_run": rec.dry_run,
                        "result_status": rec.result.get("status", ""),
                        "rollback_command": rec.rollback_command,
                    }
                )
        logger.info("Exported %d audit records to %s", len(records), output_path)
        return len(records)
