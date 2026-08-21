"""
Ollama-backed LLM provider.

Calls Ollama's native /api/chat endpoint with a JSON-schema `format`
for structured output, via httpx directly -- deliberately not the
OpenAI-compatible shim. The native endpoint's schema-constrained
`format` is a stronger guarantee than the compat layer's
`response_format: {"type": "json_object"}` (which only asks for some
valid JSON, not this specific shape), and this avoids adding the
`openai` package for a single call site.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .base import LLMProvider
from .prompt import SYSTEM_PROMPT
from .schema import RecommendationExplanation

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen2.5:3b"
DEFAULT_TIMEOUT_SECONDS = 60.0


class OllamaProvider(LLMProvider):

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:

        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")

        self.model = (
            model
            or os.getenv("OLLAMA_MODEL", DEFAULT_MODEL)
        )

        self.timeout = timeout

    def explain(
        self,
        payload: dict[str, Any],
    ) -> RecommendationExplanation:

        schema = RecommendationExplanation.model_json_schema()

        request_body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        payload,
                        ensure_ascii=False,
                        default=str,
                    ),
                },
            ],
            "stream": False,
            "format": schema,
            "options": {
                "temperature": 0,
            },
        }

        with httpx.Client(timeout=self.timeout) as client:

            response = client.post(
                f"{self.base_url}/api/chat",
                json=request_body,
            )

            response.raise_for_status()

            data = response.json()

        message = data.get("message")

        if not isinstance(message, dict):
            raise RuntimeError(
                "Ollama response is missing 'message'."
            )

        content = message.get("content")

        if not content:
            raise RuntimeError(
                "Ollama returned empty content."
            )

        return RecommendationExplanation.model_validate_json(
            content
        )
