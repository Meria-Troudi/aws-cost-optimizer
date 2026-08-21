"""
Provider-agnostic interface for the explanation layer.

Any provider (Ollama today, something else later) implements this
one method. The caller never depends on how the explanation was
produced, only on the RecommendationExplanation shape it returns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .schema import RecommendationExplanation


class LLMProvider(ABC):

    @abstractmethod
    def explain(
        self,
        payload: dict[str, Any],
    ) -> RecommendationExplanation:
        raise NotImplementedError
