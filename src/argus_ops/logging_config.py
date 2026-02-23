"""Logging configuration for Argus-Ops.

Provides two output modes:
- Stream (default): JSON-structured lines to stderr for container/systemd environments.
- File: RotatingFileHandler for long-running ``serve`` deployments so disk usage is bounded.

JSON format example:
    {"ts": "2026-02-23T10:30:00.123Z", "level": "INFO", "logger": "argus_ops.engine",
     "message": "Scan complete: 5 finding(s)"}
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{record.msecs:03.0f}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    max_bytes: int = 10 * 1024 * 1024,   # 10 MB per file
    backup_count: int = 5,
) -> None:
    """Configure JSON-structured logging for the application.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_file: Path to a rotating log file. When set, log records are written
            to both stderr AND the file. Defaults to None (stderr only).
        max_bytes: Maximum size of each log file before rotation (bytes).
            Default: 10 MB.
        backup_count: Number of rotated backup files to keep. Default: 5.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    formatter = _JsonFormatter()

    root_logger = logging.getLogger("argus_ops")
    root_logger.setLevel(numeric_level)
    root_logger.handlers.clear()
    root_logger.propagate = False

    # Always write to stderr
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)

    # Optionally write to a bounded rotating file
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        rotating_handler = logging.handlers.RotatingFileHandler(
            filename=str(file_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        rotating_handler.setFormatter(formatter)
        root_logger.addHandler(rotating_handler)
        root_logger.info(
            "File logging enabled: path=%s max_bytes=%d backup_count=%d",
            log_file,
            max_bytes,
            backup_count,
        )
