"""
Acceptance tests for the recommendation-engine rewrite.

These are the two tests the fix was designed around:

1. Multiple same-region resources of the same type (e.g. 3 idle NAT
   gateways sharing one collection-plan billing line) must produce
   one recommendation PER RESOURCE, with no unique-identity collision
   and no fabricated per-resource cost.
2. A resource-attributed, genuinely-eliminable finding (ELB idle with
   confirmed-zero traffic and no targets) must be allowed to claim
   its full cost as savings, with an explicit basis.
"""

from __future__ import annotations

from recommendations.engine import RecommendationEngine


def _nat_finding(index: int) -> dict:
    resource_id = f"nat-{index}"

    return {
        "finding_type": "nat_gateway_idle",
        "finding_key": "nat_gateway_idle",
        "resource_type": "nat_gateway",
        "resource_id": resource_id,
        "region": "eu-west-1",
        "service": "EC2 - Other",
        "severity": "medium",
        "confidence": "medium",
        "reason": (
            "No NAT traffic or connections were observed."
        ),
        "recommendation_eligible": True,
        "database_id": 100 + index,
        "limitations": [],
        "evidence_summary": [],
        "conditions": [],
        "impact": {
            "observed_monthly_cost": 350.40,
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": "cost_not_resource_attributed",
            "currency": "USD",
        },
        "evidence": {
            "billing": {
                "attribution_scope": "collection_plan",
                "amount": 350.40,
            },
        },
    }


def _elb_idle_with_cost_finding() -> dict:
    return {
        "finding_type": "elb_idle_with_cost",
        "finding_key": "elb_idle_with_cost",
        "resource_type": "load_balancer",
        "resource_id": "alb-1",
        "region": "eu-west-1",
        "service": "Amazon Elastic Load Balancing",
        "severity": "high",
        "confidence": "high",
        "reason": (
            "The load balancer has no registered targets, "
            "observed traffic was confirmed at zero, and it "
            "is incurring USD 38.10 of billed cost."
        ),
        "recommendation_eligible": True,
        "database_id": 555,
        "limitations": [],
        "evidence_summary": [],
        "conditions": [],
        "impact": {
            "observed_monthly_cost": 38.10,
            "estimated_monthly_savings": 38.10,
            "savings_confidence": "high",
            "savings_basis": "full_resource_elimination",
            "currency": "USD",
        },
        "evidence": {
            "billing": {
                "attribution_scope": "resource",
                "amount": 38.10,
            },
        },
    }


def test_three_same_region_nat_findings_produce_three_recommendations():
    """
    Acceptance test 1: 3 idle NAT gateways sharing one region/billing
    line must never collapse into one recommendation, must never
    collide on (recommendation_key, resource_type, scope), and must
    never present a slice of the shared $350.40 as if it were any
    single gateway's own cost.
    """

    findings = [_nat_finding(i) for i in (1, 2, 3)]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 3

    identities = {
        (
            r["recommendation_key"],
            r["resource_type"],
            r["scope"],
        )
        for r in recommendations
    }

    # No unique-constraint collision: 3 distinct identities.
    assert len(identities) == 3

    scopes = {r["scope"] for r in recommendations}
    assert scopes == {
        "resource:nat-1",
        "resource:nat-2",
        "resource:nat-3",
    }

    for recommendation in recommendations:
        assert (
            recommendation["financial_impact"][
                "estimated_monthly_savings"
            ]
            is None
        )
        assert (
            recommendation["source_finding_count"] == 1
        )
        assert (
            len(recommendation["affected_resources"]) == 1
        )


def test_elb_idle_with_cost_produces_one_recommendation_with_full_elimination_savings():
    """
    Acceptance test 2: a resource-attributed, confirmed-eliminable
    ELB finding must produce exactly one recommendation carrying its
    real $38.10 cost as savings, with an explicit elimination basis
    -- not a null/zero savings figure, and not silently dropped.
    """

    recommendations = RecommendationEngine().generate(
        [_elb_idle_with_cost_finding()]
    )

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert (
        recommendation["financial_impact"][
            "estimated_monthly_savings"
        ]
        == 38.10
    )
    assert (
        recommendation["financial_impact"]["savings_basis"]
        == "full_resource_elimination"
    )
    assert recommendation["scope"] == "resource:alb-1"


def test_malformed_finding_does_not_abort_the_rest_of_the_batch():
    """
    A single finding missing resource_id (required for a
    resource-scoped recommendation) must be skipped, not crash
    generation for every other finding in the same scan.
    """

    good = _nat_finding(1)
    broken = _nat_finding(2)
    broken["resource_id"] = None

    recommendations = RecommendationEngine().generate(
        [broken, good]
    )

    assert len(recommendations) == 1
    assert recommendations[0]["scope"] == "resource:nat-1"


def test_finding_without_persisted_database_id_is_skipped():
    finding = _nat_finding(1)
    finding["database_id"] = None

    recommendations = RecommendationEngine().generate(
        [finding]
    )

    assert recommendations == []
