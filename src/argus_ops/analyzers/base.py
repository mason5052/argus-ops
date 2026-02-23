"""Abstract base class for anomaly analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from argus_ops.models import Finding, FindingCategory, HealthSnapshot


class BaseAnalyzer(ABC):
    """Analyzes health snapshots to detect anomalies.

    Analyzers are rule-based (no AI) -- they check thresholds and patterns
    to produce findings that can optionally be passed to AI for diagnosis.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique analyzer name."""
        ...

    @property
    @abstractmethod
    def category(self) -> FindingCategory:
        """Finding category this analyzer produces."""
        ...

    @abstractmethod
    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        """Analyze snapshots and return detected findings.

        Args:
            snapshots: Health snapshots from collectors.

        Returns:
            List of findings (anomalies detected).
        """
        ...
