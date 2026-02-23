"""Abstract base class for infrastructure collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from argus_ops.models import HealthSnapshot, InfraType


class BaseCollector(ABC):
    """Gathers infrastructure state from a specific source.

    All collectors must implement collect() to return a list of
    HealthSnapshot objects representing the current infrastructure state.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique collector name (e.g., 'kubernetes', 'ssh')."""
        ...

    @property
    @abstractmethod
    def infra_type(self) -> InfraType:
        """Type of infrastructure this collector targets."""
        ...

    @abstractmethod
    def collect(self) -> list[HealthSnapshot]:
        """Collect current infrastructure state.

        Returns:
            List of HealthSnapshot objects representing current state.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this collector can connect to its target."""
        ...

    def validate_config(self) -> list[str]:
        """Validate configuration. Returns list of error messages."""
        return []
