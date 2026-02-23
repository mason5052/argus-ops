"""Token and cost tracking for AI provider calls."""

from __future__ import annotations

import logging
from decimal import ROUND_HALF_UP, Decimal

logger = logging.getLogger("argus_ops.ai.cost")

# Quantize to 6 decimal places (sub-cent precision for token costs)
_QUANT = Decimal("0.000001")


class CostTracker:
    """Tracks LLM token usage and estimated costs per session.

    Uses :class:`decimal.Decimal` for all monetary arithmetic to avoid
    the floating-point rounding errors that accumulate over many small
    per-token charges (e.g. $0.000002 * 10^6 tokens).
    """

    def __init__(self, limit_per_run: float = 1.0):
        self.limit_per_run: Decimal = Decimal(str(limit_per_run))
        self.total_cost_usd: Decimal = Decimal("0")
        self.total_tokens: int = 0
        self.calls: list[dict] = []

    def record(self, model: str, input_tokens: int, output_tokens: int, cost_usd: float) -> None:
        """Record a completed LLM call."""
        cost = Decimal(str(cost_usd)).quantize(_QUANT, rounding=ROUND_HALF_UP)
        self.total_cost_usd += cost
        self.total_tokens += input_tokens + output_tokens
        self.calls.append({
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": float(cost),
        })
        logger.debug(
            "LLM call: model=%s tokens=%d cost=$%.6f total=$%.6f",
            model,
            input_tokens + output_tokens,
            float(cost),
            float(self.total_cost_usd),
        )

    def budget_remaining(self) -> float:
        """Return remaining budget in USD."""
        remaining = self.limit_per_run - self.total_cost_usd
        return float(max(Decimal("0"), remaining))

    def within_budget(self) -> bool:
        """Check if we are still within the configured cost limit."""
        return self.total_cost_usd < self.limit_per_run

    def summary(self) -> dict:
        return {
            "total_calls": len(self.calls),
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(float(self.total_cost_usd), 6),
            "budget_remaining_usd": round(self.budget_remaining(), 6),
        }
