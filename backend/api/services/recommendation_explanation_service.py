"""
On-demand AI explanation generation for a recommendation.

Cache-first: never calls the LLM if an explanation is already
persisted, unless force=True. Fails safe: if the LLM is unavailable
or errors, returns the recommendation with ai_status="unavailable"
rather than raising -- the API must keep working with Ollama absent.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from aws_cost_optimizer.recommendations.explanation import (
    build_explanation_payload,
)
from aws_cost_optimizer.recommendations.llm.ollama import (
    OllamaProvider,
)
from aws_cost_optimizer.recommendations.catalog import (
    get_definition,
)
from aws_cost_optimizer.recommendations.llm.guard import (
    violations,
)
from aws_cost_optimizer.recommendations.llm.prompt import (
    PROMPT_VERSION,
)

from backend.api.presenters.finding_presenter import (
    present_finding,
)
from backend.api.presenters.recommendation_presenter import (
    present_recommendation,
)
from backend.database.repositories.recommendation_repository import (
    get_recommendation_by_id,
    save_recommendation_explanation,
)

logger = logging.getLogger(__name__)

PROVIDER_NAME = "ollama"


class RecommendationExplanationService:

    def __init__(self, db: Session):
        self.db = db

    def explain(
        self,
        recommendation_id: int,
        *,
        force: bool = False,
    ) -> dict[str, Any] | None:

        recommendation = get_recommendation_by_id(
            self.db,
            recommendation_id,
        )

        if recommendation is None:
            return None

        presented = present_recommendation(recommendation)

        if presented.get("ai_explanation") and not force:
            return presented

        finding = recommendation.primary_finding

        finding_dict = present_finding(finding) if finding is not None else None

        payload = build_explanation_payload(
            presented,
            finding_dict,
        )

        provider = OllamaProvider()

        try:
            explanation = provider.explain(payload)

        except Exception as exc:

            presented["ai_status"] = "unavailable"
            presented["ai_error"] = str(exc)

            return presented

        # never_invent is guidance, not a guarantee -- reject generated text that
        # asserts a figure the deterministic layer refused to compute.
        forbidden = violations(
            explanation.model_dump(),
            self._never_invent(presented),
        )

        if forbidden:
            logger.warning(
                "Rejecting generated explanation for recommendation %s: %s",
                recommendation_id,
                "; ".join(forbidden),
            )

            # Same fail-safe contract as an unreachable provider: never
            # raise, never persist, surface it as unavailable.
            presented["ai_status"] = "unavailable"
            presented["ai_error"] = (
                "Generated explanation asserted content the "
                "recommendation policy forbids."
            )

            return presented

        save_recommendation_explanation(
            self.db,
            recommendation_id,
            explanation.model_dump(),
            provider=PROVIDER_NAME,
            model=provider.model,
            prompt_version=PROMPT_VERSION,
        )

        self.db.commit()

        return present_recommendation(
            get_recommendation_by_id(
                self.db,
                recommendation_id,
            )
        )

    @staticmethod
    def _never_invent(presented: dict[str, Any]) -> tuple[str, ...]:
        """The forbidden-assertion list for this recommendation's route.

        Resolved from the catalog by recommendation_key. An unknown key
        yields an empty tuple, which means the guard checks nothing --
        acceptable only because a recommendation cannot be persisted
        with a key the catalog does not contain in the first place.
        """

        definition = get_definition(presented.get("recommendation_key"))

        if definition is None:
            return ()

        return tuple(getattr(definition, "never_invent", ()) or ())
