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
# Measured on real hardware: a cold call (Ollama has unloaded the model
# since the last request) takes ~108s, ~76s of which is model load, not
# generation -- a warm call is ~32s. 60s was timing out on cold calls.
DEFAULT_TIMEOUT_SECONDS = 180.0
# Keep the model resident well past Ollama's 5-minute default so a user
# clicking through several recommendations in one session only pays the
# cold-load cost once, not on every explanation.
DEFAULT_KEEP_ALIVE = "30m"


class OllamaProvider(LLMProvider):

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:

        self.base_url = (
            base_url or os.getenv("OLLAMA_BASE_URL", DEFAULT_BASE_URL)
        ).rstrip("/")

        self.model = model or os.getenv("OLLAMA_MODEL", DEFAULT_MODEL)

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
            "keep_alive": DEFAULT_KEEP_ALIVE,
            "options": {
                # Low but non-zero: temperature 0 made a small model
                # reproduce the system prompt's example sentences
                # near-verbatim across unrelated recommendations (fully
                # deterministic decoding always picks the same highest-
                # probability continuation, which the few-shot examples
                # bias toward their own exact wording). 0.3 leaves room
                # for paraphrasing without materially increasing
                # invented-fact risk -- guard.py's fact-detection is
                # shape-based (money/instance-type patterns, destructive-
                # claim wording), not tied to any particular phrasing.
                "temperature": 0.3,
                # Bound the generation window: explanations are short
                # structured output, and an uncapped 3B model can ramble
                # long past the schema's needs. Also keep the context
                # window modest -- the payload is small and a large
                # num_ctx dominates prefill time on small GPUs.
                "num_predict": 700,
                "num_ctx": 4096,
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
            raise RuntimeError("Ollama response is missing 'message'.")

        content = message.get("content")

        if not content:
            raise RuntimeError("Ollama returned empty content.")

        return RecommendationExplanation.model_validate_json(content)

    def warm_up(self) -> bool:
        """
        Load the model into memory without generating anything.

        The dominant cost of a "cold" explanation is model load
        (~76s measured), not generation. Calling this in the
        background at API startup (and keeping the model resident via
        keep_alive) means the first user-facing explanation behaves
        like a warm call.
        """

        try:

            with httpx.Client(timeout=300.0) as client:

                response = client.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": "",
                        "keep_alive": DEFAULT_KEEP_ALIVE,
                    },
                )

                response.raise_for_status()

            return True

        except Exception:

            return False
