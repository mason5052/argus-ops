"""Token and cost tracking for AI provider calls."""

from __future__ import annotations

import logging

logger = logging.getLogger("argus_ops.ai.cost")


class CostTracker:
    """Tracks LLM token usage and estimated costs per session."""

    def __init__(self, limit_per_run: float = 1.0):
        self.limit_per_run = limit_per_run
        self.total_cost_usd: float = 0.0
        self.total_tokens: int = 0
        self.calls: list[dict] = []

    def record(self, model: str, input_tokens: int, output_tokens: int, cost_usd: float) -> None:
        """Record a completed LLM call."""
        self.total_cost_usd += cost_usd
        self.total_tokens += input_tokens + output_tokens
        self.calls.append({
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": cost_usd,
        })
        logger.debug(
            "LLM call: model=%s tokens=%d cost=$%.4f total=$%.4f",
            model,
            input_tokens + output_tokens,
            cost_usd,
            self.total_cost_usd,
        )

    def budget_remaining(self) -> float:
        """Return remaining budget in USD."""
        return max(0.0, self.limit_per_run - self.total_cost_usd)

    def within_budget(self) -> bool:
        """Check if we are still within the configured cost limit."""
        return self.total_cost_usd < self.limit_per_run

    def summary(self) -> dict:
        return {
            "total_calls": len(self.calls),
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "budget_remaining_usd": round(self.budget_remaining(), 4),
        }
