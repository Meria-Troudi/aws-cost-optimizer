"""
Recommendation safety gate.

Minimal for this pass: confirms the finding is actually eligible.
Full `required_evidence` enforcement (checking that the finding's
evidence actually contains what the catalog definition demands)
is intentionally deferred -- it would require touching every
analyzer's evidence shape and isn't needed to fix the current
recommendation-generation crash.
"""

from __future__ import annotations

from typing import Any

from .catalog import RecommendationDefinition


def validate(
    finding: dict[str, Any],
    definition: RecommendationDefinition,
) -> tuple[bool, list[str]]:

    errors: list[str] = []

    if not isinstance(
        finding,
        dict,
    ):
        return False, [
            "Finding is not a mapping."
        ]

    if finding.get(
        "recommendation_eligible"
    ) is not True:

        errors.append(
            "Finding is not recommendation eligible."
        )

    if definition is None:

        errors.append(
            "No recommendation definition resolved."
        )

    elif definition.recommendation_eligible is not True:

        errors.append(
            "Recommendation definition is disabled."
        )

    return (not errors, errors)
