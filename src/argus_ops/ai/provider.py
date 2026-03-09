"""LiteLLM-based AI provider for infrastructure diagnosis."""

from __future__ import annotations

import json
import logging
import re
import uuid
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, Field, field_validator

from argus_ops.ai.base import BaseAIProvider
from argus_ops.ai.cost import CostTracker
from argus_ops.models import Diagnosis, Finding

# Maximum allowed length for raw LLM response content (32 KB)
_MAX_CONTENT_BYTES = 32_768


class _DiagnosisResponse(BaseModel):
    """Pydantic model for validating and coercing the LLM JSON response."""

    root_cause: str = "Unknown"
    explanation: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    recommendations: list[str] = []
    related_resources: list[str] = []

    @field_validator("recommendations", "related_resources", mode="before")
    @classmethod
    def coerce_to_list(cls, v: Any) -> list[str]:
        """Accept a list or a single string; reject other types."""
        if isinstance(v, list):
            return [str(item) for item in v]
        if isinstance(v, str):
            return [v]
        return []

    @field_validator("confidence", mode="before")
    @classmethod
    def coerce_confidence(cls, v: Any) -> float:
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.5

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

    # Timeout in seconds for LLM completion calls
    _LLM_TIMEOUT: int = 60

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.model = self.config.get("model", "gpt-4o-mini")
        self.temperature = self.config.get("temperature", 0.3)
        self.max_tokens = self.config.get("max_tokens", 4096)
        # Store base_url as instance variable instead of polluting global litellm state
        self._base_url: str | None = self.config.get("base_url")
        self.cost_tracker = CostTracker(
            limit_per_run=self.config.get("cost_limit_per_run", 1.0)
        )

        self._jinja_env = Environment(  # nosec B701 - prompt templates, not HTML
            loader=FileSystemLoader(str(_PROMPTS_DIR)),
            autoescape=False,
        )

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
            completion_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "timeout": self._LLM_TIMEOUT,
            }
            if self._base_url:
                completion_kwargs["api_base"] = self._base_url
            response = litellm.completion(**completion_kwargs)
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
        """Parse AI response JSON into a Diagnosis model.

        Enforces a content size limit, safely strips markdown fences,
        and validates the parsed structure with a Pydantic model.
        """
        diagnosis_id = f"DIAG-{uuid.uuid4().hex[:8]}"
        finding_ids = [f.finding_id for f in findings]
        tokens = (usage.prompt_tokens + usage.completion_tokens) if usage else 0

        # Guard against oversized LLM responses
        if len(content.encode()) > _MAX_CONTENT_BYTES:
            logger.warning(
                "AI response exceeds %d bytes, truncating", _MAX_CONTENT_BYTES
            )
            content = content.encode()[:_MAX_CONTENT_BYTES].decode(errors="replace")

        # Safely strip markdown code fences using regex (handles ```, ```json, etc.)
        cleaned = content.strip()
        fence_match = re.match(r"^```[a-z]*\n(.*?)(?:\n```)?$", cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        try:
            raw = json.loads(cleaned)
            if not isinstance(raw, dict):
                raise ValueError(f"Expected JSON object, got {type(raw).__name__}")
            validated = _DiagnosisResponse.model_validate(raw)
            return Diagnosis(
                diagnosis_id=diagnosis_id,
                finding_ids=finding_ids,
                root_cause=validated.root_cause,
                explanation=validated.explanation,
                confidence=validated.confidence,
                recommendations=validated.recommendations,
                related_resources=validated.related_resources,
                model_used=self.model,
                tokens_used=tokens,
                cost_usd=cost,
            )
        except json.JSONDecodeError:
            logger.warning("AI response is not valid JSON, using raw text as explanation")
        except Exception as exc:
            logger.warning("AI response validation failed (%s), using raw text", exc)

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
