"""
Contract tests for the recommendation evidence gate.

Every catalog route declares `required_evidence`. Before this gate
existed, nothing checked it: a route could declare `dependencies`
mandatory and still emit a "remove this resource" recommendation for a
finding that carried no dependency evidence whatsoever. The catalog
documented a safety contract that no code upheld.

These tests pin the three properties that make the gate worth having:
it accepts findings that genuinely carry the evidence, it rejects those
that do not, and it fails closed on concepts nobody has mapped.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from recommendations.catalog import RecommendationDefinition
from recommendations.policy import _CONCEPT_PROBES, missing_evidence, validate

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = (
    ROOT / "aws_cost_optimizer" / "recommendations" / "recommendation_rules.yaml"
)


def _rules() -> dict:
    with open(RULES_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _definition(**overrides) -> RecommendationDefinition:
    base = {
        "key": "review_unused",
        "family": "unused_resource",
        "action": "review_unused",
        "priority": "high",
        "recommendation_eligible": True,
        "required_evidence": ("observed_usage", "resource_state"),
        "never_invent": (),
    }
    base.update(overrides)

    return RecommendationDefinition(**base)


def _finding(**overrides) -> dict:
    finding = {
        "finding_type": "example_finding",
        "resource_id": "r-1",
        "recommendation_eligible": True,
        "evidence": {
            "metrics": {"CPUUtilization": {"value": 3.1}},
            "configuration": {"state": "available"},
            "topology": {"routes": ["r"]},
            "billing": {},
            "derived": {},
        },
        "conditions": [{"name": "status", "value": "stopped"}],
    }
    finding.update(overrides)

    return finding


# ----------------------------------------------------------------------
# Accept path
# ----------------------------------------------------------------------


def test_finding_with_required_evidence_is_accepted():
    allowed, errors = validate(_finding(), _definition())

    assert allowed, errors
    assert errors == []


def test_evidence_may_be_satisfied_from_conditions():
    """resource_state is satisfiable by a condition, not just configuration.

    Different resource types express the same concept differently --
    an EIP proves its state through an `associated` condition, an RDS
    instance through configuration.state. The gate has to accept both
    or it just encodes one analyzer's shape.
    """

    finding = _finding(
        evidence={
            "metrics": {"x": 1},
            "configuration": {},
        },
        conditions=[{"name": "associated", "value": False}],
    )

    assert missing_evidence(finding, ["resource_state"]) == []


# ----------------------------------------------------------------------
# Reject path
# ----------------------------------------------------------------------


def test_missing_evidence_is_rejected_with_a_specific_reason():
    finding = _finding(
        evidence={"configuration": {"state": "available"}},
        conditions=[],
    )

    allowed, errors = validate(finding, _definition())

    assert not allowed
    assert any("observed_usage" in error for error in errors)
    # The reason must say where it looked, or it is not actionable.
    assert any("looked in" in error for error in errors)


def test_empty_evidence_container_does_not_satisfy_a_requirement():
    """An empty metrics dict is absence of evidence, not evidence of zero.

    This is the whole point of the gate: a recommendation must not rest
    on a key that exists but holds nothing.
    """

    finding = _finding(evidence={"metrics": {}, "configuration": {}}, conditions=[])

    assert missing_evidence(finding, ["observed_usage"]) != []


def test_ineligible_finding_is_rejected():
    allowed, errors = validate(
        _finding(recommendation_eligible=False),
        _definition(),
    )

    assert not allowed
    assert any("not recommendation eligible" in error for error in errors)


def test_unknown_concept_fails_closed():
    """A concept with no resolver must reject, never silently pass.

    Failing open would recreate the exact problem this gate fixes: a
    catalog entry that documents a requirement nothing enforces.
    """

    reasons = missing_evidence(_finding(), ["a_concept_nobody_mapped"])

    assert len(reasons) == 1
    assert "no resolver defined" in reasons[0]


# ----------------------------------------------------------------------
# Catalog/gate consistency
# ----------------------------------------------------------------------


def test_every_catalog_required_evidence_concept_has_a_resolver():
    """The catalog must not declare evidence the gate cannot evaluate.

    Without this, adding a concept to recommendation_rules.yaml would
    silently reject every finding on that route -- failing closed is
    right, but failing closed *invisibly* is not.
    """

    declared: set[str] = set()

    for definition in (_rules().get("recommendations") or {}).values():
        for concept in definition.get("required_evidence") or []:
            declared.add(str(concept).strip())

    unmapped = sorted(concept for concept in declared if concept not in _CONCEPT_PROBES)

    assert not unmapped, (
        "catalog declares required_evidence concepts with no resolver in "
        f"policy._CONCEPT_PROBES: {unmapped}"
    )
