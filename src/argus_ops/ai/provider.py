"""LiteLLM-based AI provider for infrastructure diagnosis."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from argus_ops.ai.base import BaseAIProvider
from argus_ops.ai.cost import CostTracker
from argus_ops.models import Diagnosis, Finding

logger = logging.getLogger("argus_ops.ai.provider")

_PROMPTS_DIR = Path(__file__).parent / "prompts"


class LiteLLMProvider(BaseAIProvider):
    """Unified AI provider using LiteLLM for any LLM backend.

    Supports OpenAI, Anthropic, Ollama (local), Azure OpenAI,
    Amazon Bedrock, Google Gemini, and 100+ other providers
    via the litellm unified API.

    Usage:
        provider = LiteLLMProvider({
            "model": "gpt-4o-mini",
            "api_key_env": "OPENAI_API_KEY",
        })
        diagnosis = provider.diagnose(findings, context)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.model = self.config.get("model", "gpt-4o-mini")
        self.temperature = self.config.get("temperature", 0.3)
        self.max_tokens = self.config.get("max_tokens", 4096)
        self.cost_tracker = CostTracker(
            limit_per_run=self.config.get("cost_limit_per_run", 1.0)
        )

        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_PROMPTS_DIR)),
            autoescape=False,
        )

        # Apply custom base URL if configured (e.g., for Ollama)
        base_url = self.config.get("base_url")
        if base_url:
            import litellm
            litellm.api_base = base_url

    def diagnose(self, findings: list[Finding], context: dict[str, Any]) -> Diagnosis:
        """Generate root cause diagnosis from a list of findings."""
        import litellm

        if not findings:
            return Diagnosis(
                diagnosis_id=f"DIAG-{uuid.uuid4().hex[:8]}",
                root_cause="No findings to diagnose",
                explanation="The scan did not produce any findings.",
                confidence=1.0,
            )

        if not self.cost_tracker.within_budget():
            logger.warning("Cost budget exceeded, skipping AI diagnosis")
            return Diagnosis(
                diagnosis_id=f"DIAG-{uuid.uuid4().hex[:8]}",
                root_cause="Budget limit reached",
                explanation="AI diagnosis skipped: configured cost limit exceeded.",
                confidence=0.0,
            )

        prompt = self._render_diagnosis_prompt(findings, context)

        logger.info(
            "Calling AI model %s to diagnose %d finding(s)", self.model, len(findings)
        )

        try:
            response = litellm.completion(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
        except Exception as e:
            logger.error("AI diagnosis failed: %s", e)
            return Diagnosis(
                diagnosis_id=f"DIAG-{uuid.uuid4().hex[:8]}",
                finding_ids=[f.finding_id for f in findings],
                root_cause="AI diagnosis unavailable",
                explanation=f"Could not reach AI model ({self.model}): {e}",
                confidence=0.0,
            )

        # Track cost
        usage = response.usage
        cost = self._estimate_cost(
            self.model,
            usage.prompt_tokens if usage else 0,
            usage.completion_tokens if usage else 0,
        )
        self.cost_tracker.record(
            self.model,
            usage.prompt_tokens if usage else 0,
            usage.completion_tokens if usage else 0,
            cost,
        )

        content = response.choices[0].message.content or ""
        return self._parse_diagnosis(content, findings, usage, cost)

    def _render_diagnosis_prompt(
        self, findings: list[Finding], context: dict[str, Any]
    ) -> str:
        """Render the diagnosis prompt template."""
        template = self._jinja_env.get_template("diagnose.j2")
        return template.render(findings=findings, context=context)

    def _parse_diagnosis(
        self,
        content: str,
        findings: list[Finding],
        usage: Any,
        cost: float,
    ) -> Diagnosis:
        """Parse AI response JSON into a Diagnosis model."""
        diagnosis_id = f"DIAG-{uuid.uuid4().hex[:8]}"
        finding_ids = [f.finding_id for f in findings]
        tokens = (usage.prompt_tokens + usage.completion_tokens) if usage else 0

        # Strip markdown code fences if present
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            cleaned = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        try:
            data = json.loads(cleaned)
            return Diagnosis(
                diagnosis_id=diagnosis_id,
                finding_ids=finding_ids,
                root_cause=data.get("root_cause", "Unknown"),
                explanation=data.get("explanation", content),
                confidence=float(data.get("confidence", 0.5)),
                recommendations=data.get("recommendations", []),
                related_resources=data.get("related_resources", []),
                model_used=self.model,
                tokens_used=tokens,
                cost_usd=cost,
            )
        except (json.JSONDecodeError, ValueError):
            logger.warning("Could not parse AI response as JSON, using raw text")
            return Diagnosis(
                diagnosis_id=diagnosis_id,
                finding_ids=finding_ids,
                root_cause="See explanation",
                explanation=content,
                confidence=0.5,
                model_used=self.model,
                tokens_used=tokens,
                cost_usd=cost,
            )

    @staticmethod
    def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost in USD for a completion call."""
        try:
            import litellm
            return litellm.completion_cost(
                model=model,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
            )
        except Exception:
            return 0.0
