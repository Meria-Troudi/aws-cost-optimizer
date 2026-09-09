"""
Acceptance tests for the recommendation engine.

There is no catalog-level flag governing aggregation. Findings group into
one recommendation exactly when they share every part of
`(recommendation_key, service, resource_type, region, finding_type)` --
`finding_type` is deliberately IN the key: different finding_types never
merge, even on the same resource, because they represent different
conditions with different evidence. `recommendation_variant` (set to the
group's finding_type) is what lets two different finding_type groups
persist under the same resource-scoped `scope` without colliding on the
DB's (scan_run_id, recommendation_key, recommendation_variant,
resource_type, scope) unique constraint.

1. 3 idle NAT gateways (same finding_type) sharing one collection-plan
   billing line merge into one region-scoped recommendation carrying the
   shared $350.40 bucket cost once (never multiplied or sliced per
   gateway).
2. 3 unassociated EIPs (same finding_type) in one region merge into a
   single region-scoped recommendation listing every allocation.
3. A resource-attributed, genuinely-eliminable finding (ELB idle with
   cost) claims its full cost as savings with an explicit basis.
4. Different finding_types on one resource stay separate recommendations.
5. Account-scoped commitment findings (Savings Plans) still aggregate
   across every matching resource in the account -- that was never
   actually driven by the removed `aggregate` flag, it falls out of
   `recommendation_scope: account` producing one shared `scope` string
   regardless of resource or finding_type.
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
        "reason": ("No NAT traffic or connections were observed."),
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
        # Mirrors the evidence shape a real nat_gateway_idle finding
        # carries (verified against persisted scan output), so this
        # fixture passes the required_evidence gate the same way a real
        # finding does rather than bypassing it.
        "evidence": {
            "billing": {
                "attribution_scope": "collection_plan",
                "amount": 350.40,
            },
            "metrics": {
                "BytesInFromSource": {"value": 0, "has_data": True},
                "ActiveConnectionCount": {"value": 0, "has_data": True},
            },
            "configuration": {
                "nat_gateway_id": resource_id,
                "state": "available",
            },
            "derived": {
                "traffic": {
                    "directional_traffic_bytes": 0,
                    "observed": False,
                    "complete": True,
                },
            },
            "topology": {
                "nat_routes": [{"route_table_id": "rtb-1"}],
                "route_dependent_subnet_ids": ["subnet-1"],
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
        # As above: real elb_idle_with_cost evidence, so the gate is
        # exercised rather than sidestepped.
        "evidence": {
            "billing": {
                "attribution_scope": "resource",
                "amount": 38.10,
            },
            "metrics": {
                "request_count": {"value": 0, "has_data": True},
                "processed_bytes": {"value": 0, "has_data": True},
            },
            "configuration": {
                "load_balancer_name": "alb-1",
                "load_balancer_arn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/alb-1/1",
                "state": "active",
            },
            "topology": {
                "subnets": ["subnet-1"],
                "route_tables": ["rtb-1"],
            },
        },
        "conditions": [
            {"name": "target_count", "value": 0},
            {"name": "target_health_complete", "value": True},
        ],
    }


def test_three_same_region_nat_findings_merge_into_one_recommendation():
    """
    Acceptance test 1: 3 idle NAT gateways -- all `nat_gateway_idle`,
    sharing one region/billing line -- merge into ONE region-scoped
    recommendation listing all three gateways. Findings sharing every
    part of the aggregation key (recommendation_key, service,
    resource_type, region, finding_type) always merge; there's no
    catalog-level opt-in for it. The shared $350.40 bucket cost is
    carried once, never multiplied or sliced per gateway.
    """

    findings = [_nat_finding(i) for i in (1, 2, 3)]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["recommendation_key"] == "review_nat_gateway_removal"
    assert recommendation["recommendation_variant"] == "nat_gateway_idle"
    assert recommendation["affected_resource_count"] == 3
    assert sorted(recommendation["affected_resources"]) == ["nat-1", "nat-2", "nat-3"]
    assert recommendation["source_finding_count"] == 3
    # Group identity, so the merged row cannot collide with a sibling.
    assert recommendation["scope"] == "region:eu-west-1"
    # Shared $350.40 bucket: carried once, never multiplied or sliced.
    assert recommendation["financial_impact"]["observed_monthly_cost"] == 350.40
    assert (
        recommendation["financial_impact"]["savings_basis"]
        == "cost_not_resource_attributed"
    )


def test_three_unassociated_eips_merge_into_one_regional_recommendation():
    """
    Same rule as the NAT test above, applied to EIPs: 3
    `elastic_ip_unassociated` findings share the full aggregation key
    (recommendation_key, service, resource_type, region, finding_type),
    so they merge into ONE region-scoped recommendation listing every
    allocation and preserving every source finding id.
    """

    def _eip_finding(index: int, resource_id: str) -> dict:
        return {
            "database_id": index,
            "finding_type": "elastic_ip_unassociated",
            "resource_id": resource_id,
            "resource_type": "elastic_ip",
            "severity": "medium",
            "confidence": "high",
            "reason": "The Elastic IP is allocated but not associated.",
            "recommendation_eligible": True,
            "region": "eu-west-1",
            "service": "Amazon Virtual Private Cloud",
            "account_id": "123456789012",
            "conditions": [
                {"name": "resource_identity", "value": resource_id},
                {"name": "association_state", "value": {"associated": False}},
                {"name": "observed_state", "value": "idle"},
            ],
            "evidence": {"configuration": {"associated": False, "state": "idle"}},
            "evidence_summary": ["associated: false", "state: idle"],
            "impact": {},
            "limitations": [],
            "observation_period": {"start": "2026-08-01", "end": "2026-08-29"},
        }

    findings = [
        _eip_finding(1, "eipalloc-08834aaa"),
        _eip_finding(2, "eipalloc-060bbbb"),
        _eip_finding(3, "eipalloc-0b9cccc"),
    ]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["recommendation_key"] == "release_unassociated_public_ipv4"
    assert recommendation["recommendation_variant"] == "elastic_ip_unassociated"
    assert recommendation["affected_resource_count"] == 3
    assert sorted(recommendation["affected_resources"]) == [
        "eipalloc-060bbbb",
        "eipalloc-08834aaa",
        "eipalloc-0b9cccc",
    ]
    # Group identity, not one resource's -- otherwise the DB unique
    # constraint on (scan_run_id, recommendation_key, ..., scope) collides.
    assert recommendation["scope"] == "region:eu-west-1"
    # Every source finding stays traceable through the merge.
    assert sorted(recommendation["source_finding_ids"]) == [1, 2, 3]


def test_recommendation_carries_a_deterministic_plan_without_aws_operations():
    """
    Every recommendation carries its catalog procedure as a deterministic
    `plan` -- humanized validation_steps/possible_actions the UI can
    render without the LLM, and without ever handing out AWS operation
    names (which are the raw material for a hallucinated CLI command;
    see recommendations/plan.py and llm/guard.py).
    """

    recommendations = RecommendationEngine().generate([_nat_finding(1)])

    assert len(recommendations) == 1

    plan = recommendations[0]["plan"]

    assert plan
    assert plan["objective"]
    assert plan["validation_steps"]
    assert plan["possible_actions"]
    assert "aws_operations" not in plan
    # Humanized, not the raw snake_case slug.
    assert all("_" not in step for step in plan["validation_steps"])


def test_elb_idle_with_cost_produces_one_recommendation_with_full_elimination_savings():
    """
    Acceptance test 2: a resource-attributed, confirmed-eliminable
    ELB finding must produce exactly one recommendation carrying its
    real $38.10 cost as savings, with an explicit elimination basis
    -- not a null/zero savings figure, and not silently dropped.
    """

    recommendations = RecommendationEngine().generate([_elb_idle_with_cost_finding()])

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["financial_impact"]["estimated_monthly_savings"] == 38.10
    assert (
        recommendation["financial_impact"]["savings_basis"]
        == "full_resource_elimination"
    )
    # review_load_balancer_removal is also aggregate: false -- resource
    # identity, not a region-level group identity, even for one member.
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

    recommendations = RecommendationEngine().generate([broken, good])

    assert len(recommendations) == 1
    assert recommendations[0]["affected_resources"] == ["nat-1"]


def test_finding_without_persisted_database_id_is_skipped():
    finding = _nat_finding(1)
    finding["database_id"] = None

    recommendations = RecommendationEngine().generate([finding])

    assert recommendations == []


def test_different_finding_types_on_one_resource_stay_separate_recommendations():
    """
    Different finding_types never merge, even on the same resource --
    they represent different conditions with different evidence, and a
    merged recommendation must not silently present one finding's
    specific reason as if it covered a different condition too.

    An idle ELB emits several findings that all route to
    review_load_balancer_removal. finding_type IS part of the
    aggregation key, so this produces 3 recommendations, not 1 -- each
    keeps its own resource-scoped identity (resource:<arn>), and
    `recommendation_variant` (set to the finding_type) is what stops
    them from colliding on the DB's (scan_run_id, recommendation_key,
    recommendation_variant, resource_type, scope) unique constraint,
    since all 3 would otherwise share the identical
    (recommendation_key, resource_type, scope) tuple.
    """

    def _elb_finding(index: int, finding_type: str, severity: str) -> dict:
        return {
            "database_id": index,
            "finding_type": finding_type,
            "resource_id": "arn:lb-1",
            "resource_type": "load_balancer",
            "severity": severity,
            "confidence": "high",
            "reason": f"{finding_type} reason",
            "recommendation_eligible": True,
            "region": "eu-west-1",
            "service": "Elastic Load Balancing",
            "account_id": "123456789012",
            "conditions": [
                {"name": "resource_identity", "value": "arn:lb-1"},
                {"name": "target_count", "value": 0},
                {"name": "resource_state", "value": "active"},
            ],
            "evidence": {"configuration": {"state": "active", "target_count": 0}},
            "evidence_summary": ["target count: 0"],
            "impact": {},
            "limitations": [],
            "observation_period": {"start": "2026-07-31", "end": "2026-08-28"},
        }

    findings = [
        _elb_finding(1, "elb_idle_with_cost", "high"),
        _elb_finding(2, "elb_no_observed_activity", "low"),
        _elb_finding(3, "elb_no_registered_targets", "medium"),
    ]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 3

    by_variant = {r["recommendation_variant"]: r for r in recommendations}

    assert set(by_variant) == {
        "elb_idle_with_cost",
        "elb_no_observed_activity",
        "elb_no_registered_targets",
    }

    for recommendation in recommendations:
        assert recommendation["recommendation_key"] == "review_load_balancer_removal"
        assert recommendation["scope"] == "resource:arn:lb-1"
        assert recommendation["affected_resources"] == ["arn:lb-1"]
        assert recommendation["source_finding_ids"] == [
            {"elb_idle_with_cost": 1, "elb_no_observed_activity": 2}.get(
                recommendation["recommendation_variant"], 3
            )
        ]

    # Each recommendation's own severity is preserved, not flattened to
    # the highest one in the whole batch.
    assert by_variant["elb_idle_with_cost"]["priority"] == "high"
    assert by_variant["elb_no_observed_activity"]["priority"] == "low"
    assert by_variant["elb_no_registered_targets"]["priority"] == "medium"


def test_one_nat_gateway_with_two_finding_types_produces_two_recommendations():
    """
    The other half of the same rule: a single NAT gateway that is BOTH
    idle and has no route dependency is two distinct, evidence-backed
    conditions -- not one blended story -- so it must produce two
    recommendations, disambiguated by recommendation_variant since they
    share one resource-scoped identity.
    """

    def _finding(finding_type: str, reason: str) -> dict:
        return {
            "database_id": 1 if finding_type == "nat_gateway_idle" else 2,
            "finding_type": finding_type,
            "resource_id": "nat-shared",
            "resource_type": "nat_gateway",
            "severity": "medium",
            "confidence": "high",
            "reason": reason,
            "recommendation_eligible": True,
            "region": "eu-west-1",
            "service": "EC2 - Other",
            "account_id": "123456789012",
            "conditions": [],
            "evidence": {
                "billing": {"attribution_scope": "collection_plan", "amount": 100.0},
                "metrics": {
                    "BytesInFromSource": {"value": 0, "has_data": True},
                    "ActiveConnectionCount": {"value": 0, "has_data": True},
                },
                "configuration": {"nat_gateway_id": "nat-shared", "state": "available"},
                "topology": {
                    "nat_routes": [],
                    "route_dependent_subnet_ids": [],
                },
            },
            "evidence_summary": [],
            "impact": {},
            "limitations": [],
            "observation_period": {"start": "2026-07-31", "end": "2026-08-28"},
        }

    findings = [
        _finding("nat_gateway_idle", "No traffic or connections were observed."),
        _finding(
            "nat_gateway_no_route_dependency",
            "No effective route currently targets this NAT Gateway.",
        ),
    ]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 2

    scopes = {r["scope"] for r in recommendations}
    variants = {r["recommendation_variant"] for r in recommendations}

    assert scopes == {"resource:nat-shared"}
    assert variants == {"nat_gateway_idle", "nat_gateway_no_route_dependency"}


def test_account_scoped_commitment_findings_still_aggregate_across_resources():
    """
    Proves removing the `aggregate` flag didn't break the one case it
    actually mattered for historically: account-level commitment
    recommendations (Savings Plans, Reserved Instances). Two
    `rds_reserved_instance_candidate` findings on two different RDS
    instances still merge into one recommendation, because
    `recommendation_scope: account` makes `resolve_persistence_scope`
    produce the identical `account:<id>` scope for both regardless of
    resource_id -- aggregation here was never really gated by the flag.

    The fixture uses `rds_reserved_instance_candidate` (the surviving
    account-scoped route); the legacy `ec2_stable_long_running` type is
    no longer emitted by the EC2 analyzer.
    """

    def _rds_finding(index: int, instance_id: str) -> dict:
        return {
            "database_id": index,
            "finding_type": "rds_reserved_instance_candidate",
            "resource_id": instance_id,
            "resource_type": "rds_instance",
            "severity": "medium",
            "confidence": "high",
            "reason": "The instance shows stable, long-running usage.",
            "recommendation_eligible": True,
            "region": "eu-west-1",
            "service": "Amazon Relational Database Service",
            "account_id": "123456789012",
            "conditions": [
                {"name": "resource_identity", "value": instance_id},
            ],
            "evidence": {
                "configuration": {"db_instance_identifier": instance_id},
                "billing": {"eligible_usage": True, "pricing_eligibility": True},
                "derived": {"usage_stability": "stable", "historical_usage": "30d"},
            },
            "evidence_summary": [],
            "impact": {},
            "limitations": [],
            "observation_period": {"start": "2026-08-01", "end": "2026-08-29"},
        }

    findings = [
        _rds_finding(1, "db-aaaaaaaa"),
        _rds_finding(2, "db-bbbbbbbb"),
    ]

    recommendations = RecommendationEngine().generate(findings)

    assert len(recommendations) == 1

    recommendation = recommendations[0]

    assert recommendation["recommendation_key"] == "rds_purchase_reserved_instance"
    assert recommendation["scope"] == "account:123456789012"
    assert recommendation["affected_resource_count"] == 2
    assert sorted(recommendation["affected_resources"]) == ["db-aaaaaaaa", "db-bbbbbbbb"]
