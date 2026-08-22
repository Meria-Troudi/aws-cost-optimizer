"""
Contract tests for never_invent enforcement on LLM output.

Each catalog route declares a `never_invent` list. It was passed to the
model as prompt guidance and never validated -- so a model was free to
answer "remove this and save $38.10/month" for a recommendation whose
whole point was that the savings could not be established, and nothing
would notice.

These tests pin the guard's two jobs: catch concrete assertions the
route forbids, and leave hedged review language alone. The second
matters as much as the first -- these recommendations are supposed to
say "review whether this is still required", and a guard that flags
that is worse than no guard.
"""

from __future__ import annotations

from recommendations.llm.guard import detectable_concepts, violations


def _explanation(**overrides) -> dict:
    base = {
        "summary": "The load balancer has no registered targets.",
        "why": "No traffic was observed during the analysis period.",
        "action": "Review whether the load balancer is still required.",
        "confidence_note": "Target health data was complete.",
        "risk": "Confirm DNS, listeners and failover before removing it.",
    }
    base.update(overrides)

    return base


# ----------------------------------------------------------------------
# Must not fire on legitimate output
# ----------------------------------------------------------------------


def test_hedged_review_language_is_allowed():
    """The language these recommendations are supposed to use."""

    assert (
        violations(
            _explanation(),
            ["savings", "deletion_safety", "replacement_resource"],
        )
        == []
    )


def test_discussing_cost_without_asserting_savings_is_allowed():
    """Naming the observed cost is fine; promising a saving is not."""

    explanation = _explanation(
        summary=("The gateway incurs recurring cost while showing no traffic."),
        why="Observed cost is attributed at the collection-plan level.",
    )

    assert violations(explanation, ["savings"]) == []


def test_empty_explanation_is_not_a_violation():
    assert violations({}, ["savings"]) == []


# ----------------------------------------------------------------------
# Must fire on forbidden assertions
# ----------------------------------------------------------------------


def test_concrete_savings_figure_is_rejected():
    explanation = _explanation(action="Remove it and save $38.10 per month.")

    found = violations(explanation, ["savings"])

    assert found
    assert "savings" in found[0]


def test_percentage_savings_claim_is_rejected():
    explanation = _explanation(summary="Switching now saves 63% of the monthly bill.")

    assert violations(explanation, ["savings"])


def test_deletion_safety_claim_is_rejected():
    explanation = _explanation(risk="It is safe to delete this volume.")

    assert violations(explanation, ["deletion_safety"])


def test_concrete_replacement_type_is_rejected():
    explanation = _explanation(action="Resize the instance to db.t3.medium.")

    assert violations(explanation, ["replacement_resource"])


def test_only_concepts_the_route_forbids_are_checked():
    """A route that permits savings talk must not be policed for it."""

    explanation = _explanation(action="Remove it and save $38.10 per month.")

    assert violations(explanation, ["deletion_safety"]) == []


# ----------------------------------------------------------------------
# Coverage honesty
# ----------------------------------------------------------------------


def test_guard_covers_the_catalogs_most_common_forbidden_concepts():
    """The concepts worth catching must actually have detectors.

    The guard deliberately under-detects rather than over-detects, but
    'savings' appears on 16 of the catalog's routes and is the single
    most damaging thing a model can invent here -- if that one silently
    had no detector, the guard would be decorative.
    """

    covered = detectable_concepts()

    for concept in ("savings", "deletion_safety", "replacement_resource"):
        assert concept in covered
