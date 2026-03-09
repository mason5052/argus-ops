"""Abstract base class for anomaly analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from argus_ops.models import Finding, FindingCategory, HealthSnapshot


class BaseAnalyzer(ABC):
    """Analyzes health snapshots to detect anomalies."""

    def __init__(self, config: dict | None = None):
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

    @property
    def required_capabilities(self) -> list[str]:
        """Capabilities this analyzer expects to be present in snapshots."""
        return []

    def supports(self, available_capabilities: set[str]) -> bool:
        """Return True when all required capabilities are available."""
        return all(
            capability in available_capabilities
            for capability in self.required_capabilities
        )

    @abstractmethod
    def analyze(self, snapshots: list[HealthSnapshot]) -> list[Finding]:
        """Analyze snapshots and return detected findings."""
        ...
