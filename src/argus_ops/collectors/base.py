"""Abstract base class for infrastructure collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from argus_ops.models import HealthSnapshot, InfraType, InventorySnapshot


class BaseCollector(ABC):
    """Gathers infrastructure state from a specific source."""

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

    @property
    def provided_capabilities(self) -> list[str]:
        """Capabilities emitted by this collector."""
        return []

    @abstractmethod
    def collect(self) -> list[HealthSnapshot]:
        """Collect current infrastructure health snapshots."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this collector can connect to its target."""
        ...

    def discover(self) -> InventorySnapshot | None:
        """Discover inventory assets for this collector."""
        return None

    def validate_config(self) -> list[str]:
        """Validate configuration. Returns list of error messages."""
        return []
