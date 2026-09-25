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


# Must not fire on legitimate output


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


# Must fire on forbidden assertions


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


def test_forbidden_assertion_hidden_inside_limitations_is_rejected():
    """
    limitations is model-generated now (not analyzer-supplied), so a
    forbidden assertion buried in a "caveat" sentence must be caught
    just like one in any other field.
    """

    explanation = _explanation(
        limitations=["Note: switching now saves $38.10 per month."]
    )

    found = violations(explanation, ["savings"])

    assert found
    assert "savings" in found[0]


def test_only_concepts_the_route_forbids_are_checked():
    """A route that permits savings talk must not be policed for it."""

    explanation = _explanation(action="Remove it and save $38.10 per month.")

    assert violations(explanation, ["deletion_safety"]) == []


# Unconditional checks: commands and account-scope widening
#
# These run regardless of the route's never_invent list, because this
# system never hands out remediation commands, and a finding's evidence
# is always scoped to one resource -- see llm/guard.py module docstring.


def test_aws_cli_command_is_rejected_even_when_not_in_never_invent():
    explanation = _explanation(
        action="Run aws ec2 release-address --allocation-id eipalloc-1234."
    )

    found = violations(explanation, [])

    assert found
    assert any("aws_cli_command" in reason for reason in found)


def test_bare_aws_operation_name_is_rejected():
    explanation = _explanation(action="Use describe-nat-gateways to confirm state.")

    found = violations(explanation, [])

    assert found
    assert any("aws_cli_command" in reason for reason in found)


def test_account_wide_generalization_is_rejected():
    explanation = _explanation(
        why="The AWS account has no active connections or diagnostics data."
    )

    found = violations(explanation, [])

    assert found
    assert any("account_scope_widening" in reason for reason in found)


def test_resource_scoped_statement_is_allowed():
    """The correctly-scoped equivalent of the account-wide claim above."""

    explanation = _explanation(
        why="This NAT Gateway had no active connections during the observed period."
    )

    assert violations(explanation, []) == []


# Coverage honesty


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


def test_dependency_and_requirement_absence_claims_are_rejected():
    """A family of catalog concepts share one claim shape: asserting no

    dependency/requirement exists for something the deterministic layer
    explicitly did not establish absence of (rds_delete_unused_database
    alone forbids dependency, business_requirement, and
    recovery_requirement). Confirm each has a working detector, not
    just an entry in the concept-pattern table.
    """

    cases = {
        "dependency": "The instance has no dependencies and can be reviewed.",
        "business_requirement": "This is not a business requirement.",
        "recovery_requirement": "There is no recovery requirement here.",
        "production_requirement": "The resource is not used in production.",
    }

    for concept, text in cases.items():
        found = violations(_explanation(why=text), [concept])
        assert found, f"{concept}: expected a violation for {text!r}"


def test_dependency_review_language_is_still_allowed():
    """The hedged form of the same claims must not be flagged -- these

    recommendations are supposed to say the absence hasn't been established,
    and a guard that rejects that sentence is worse than no guard.
    """

    text = (
        "Dependency and business requirement have not been established "
        "by the supplied evidence and require manual validation."
    )

    found = violations(
        _explanation(why=text),
        ["dependency", "business_requirement", "recovery_requirement"],
    )

    assert found == []
