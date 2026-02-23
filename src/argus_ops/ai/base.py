"""Abstract base class for AI providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from argus_ops.models import Diagnosis, Finding


class BaseAIProvider(ABC):
    """Interface for LLM backends used for diagnosis."""

    @abstractmethod
    def diagnose(self, findings: list[Finding], context: dict[str, Any]) -> Diagnosis:
        """Generate root cause diagnosis from findings.

        Args:
            findings: List of detected anomalies.
            context: Additional infrastructure context (topology, history).

        Returns:
            AI-generated diagnosis with root cause and recommendations.
        """
        ...
