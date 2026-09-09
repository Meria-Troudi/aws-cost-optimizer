"""
Structured output schema for recommendation explanations.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class RecommendationExplanation(BaseModel):

    summary: str = Field(
        description=(
            "One concise sentence identifying the recommendation and "
            "affected resource."
        )
    )

    why: str = Field(
        description=(
            "One or two sentences explaining the evidence supporting "
            "the deterministic recommendation."
        )
    )

    action: str = Field(
        description=(
            "One or two sentences explaining why the supplied plan's "
            "validation steps apply here, in plain language."
        )
    )

    what_to_verify: list[str] = Field(
        default_factory=list,
        description=(
            "Zero to six plain-language validation checks the engineer "
            "should perform, humanized ONLY from the supplied plan's "
            "validation_steps. Never a command, API call, or console "
            "path, and never a step the plan does not contain."
        ),
    )

    possible_actions: list[str] = Field(
        default_factory=list,
        description=(
            "Zero to four plain-language options the engineer may take "
            "after validation, humanized ONLY from the supplied plan's "
            "possible_actions. Never assert that any option is safe or "
            "guaranteed."
        ),
    )

    confidence_note: str = Field(
        description=(
            "Explains the supplied confidence level without changing it "
            "or recomputing it."
        )
    )

    risk: str = Field(
        description=(
            "Concise description of what could make the action "
            "inappropriate, based only on supplied evidence."
        )
    )

    limitations: list[str] = Field(
        default_factory=list,
        description=(
            "Zero to four genuine evidence limitations or unresolved "
            "validation requirements. Never invent generic caveats."
        ),
    )
