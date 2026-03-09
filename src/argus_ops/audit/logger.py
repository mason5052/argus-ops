"""Layer 1: Argus-Ops operation JSONL logger with daily rotation."""

from __future__ import annotations

import csv
import logging
from datetime import date, timedelta
from pathlib import Path

from argus_ops.audit.models import AuditRecord, RiskLevel

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSONL logger for Argus-Ops operations and API access."""

    def __init__(self, audit_dir: str | Path | None = None) -> None:
        if audit_dir is None:
            audit_dir = Path.home() / ".argus-ops" / "audit"
        self._dir = Path(audit_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _file_for_date(self, value: date) -> Path:
        return self._dir / f"{value.isoformat()}.jsonl"

    def log(self, record: AuditRecord) -> None:
        path = self._file_for_date(record.timestamp.date())
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json() + "\n")
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
                    if not line.strip():
                        continue
                    try:
                        record = AuditRecord.model_validate_json(line)
                    except Exception:
                        continue
                    if actor and actor.lower() not in record.actor.lower():
                        continue
                    if action and action.lower() not in record.action.lower():
                        continue
                    if risk_level and record.risk_level < risk_level:
                        continue
                    if source and record.source != source:
                        continue
                    records.append(record)
                    if len(records) >= limit:
                        return records
            current = current + timedelta(days=1)
        return records

    def export_csv(
        self,
        output_path: str | Path,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> int:
        records = self.query(start_date=start_date, end_date=end_date, limit=100_000)
        fields = [
            "id",
            "timestamp",
            "actor",
            "role",
            "session_id",
            "request_id",
            "source",
            "action",
            "intent",
            "http_method",
            "path",
            "target",
            "reason",
            "risk_level",
            "status_code",
            "command",
            "dry_run",
            "result_status",
            "rollback_command",
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for record in records:
                writer.writerow(
                    {
                        "id": record.id,
                        "timestamp": record.timestamp.isoformat(),
                        "actor": record.actor,
                        "role": record.role,
                        "session_id": record.session_id,
                        "request_id": record.request_id,
                        "source": record.source,
                        "action": record.action,
                        "intent": record.intent.value,
                        "http_method": record.http_method,
                        "path": record.path,
                        "target": record.target,
                        "reason": record.reason,
                        "risk_level": record.risk_level.value,
                        "status_code": record.status_code,
                        "command": record.command,
                        "dry_run": record.dry_run,
                        "result_status": record.result.get("status", ""),
                        "rollback_command": record.rollback_command,
                    }
                )
        logger.info("Exported %d audit records to %s", len(records), output_path)
        return len(records)
