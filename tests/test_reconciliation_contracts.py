"""
Contract tests for cost-attribution reconciliation.

Every case here reproduces a real scenario from a live scan (#38):
one ALB whose entire billing line is genuinely its own cost, three
NAT gateways sharing one line where no single gateway may claim it,
and an RDS instance whose billing identity belongs to a different
instance class than the one actually running. Before the fix, the
attribution verdict was computed from `bool(expected_identity)` alone,
*before* resources were even matched -- so the RDS mismatch case below
returned `cost_attribution: "resource"` while `matched_resource_ids`
was empty, and every other case landed on `collection_plan` regardless
of how many resources actually shared the bill.
"""

from __future__ import annotations

from analysis.reconciliation import reconcile_collection_plan


def _resource(resource_id: str, **configuration) -> dict:
    return {
        "resource_id": resource_id,
        "configuration": configuration,
        "identity": {},
    }


def test_sole_matching_resource_with_complete_collection_is_claimable():
    plan = {
        "service": "Amazon Elastic Load Balancing",
        "usage_type": "EU-LoadBalancerUsage",
        "region": "eu-west-1",
        "cost_context": 38.10,
        "resource_type": "load_balancer",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("alb-1")],
        collection_complete=True,
    )

    assert result["cost_attribution"] == "resource"
    assert result["resource_cost_attributed"] is True
    assert result["claimable_resource_cost"] == 38.10


def test_shared_bill_across_multiple_resources_is_not_claimable():
    plan = {
        "service": "EC2 - Other",
        "usage_type": "EU-NatGateway-Hours",
        "region": "eu-west-1",
        "cost_context": 350.40,
        "resource_type": "nat_gateway",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("nat-1"), _resource("nat-2"), _resource("nat-3")],
        collection_complete=True,
    )

    assert result["cost_attribution"] == "collection_plan"
    assert result["resource_cost_attributed"] is False
    assert result["claimable_resource_cost"] is None
    # Still available as shared evidence.
    assert result["cost"] == 350.40


def test_billing_identity_mismatch_stays_historical_never_resource():
    """
    Billing says db.t3.large; the discovered instance is db.r6g.large.
    This must never be presented as db.r6g.large's cost -- regardless
    of expected_identity being truthy, which is exactly the bug this
    test guards against.
    """

    plan = {
        "service": "Amazon Relational Database Service",
        "usage_type": "EU-InstanceUsage:db.t3.large",
        "region": "eu-west-1",
        "cost_context": 243.14,
        "resource_type": "rds_instance",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("rds-1", instance_class="db.r6g.large")],
        collection_complete=True,
    )

    assert result["status"] == "current_mismatch"
    assert result["cost_attribution"] != "resource"
    assert result["resource_cost_attributed"] is False
    assert result["claimable_resource_cost"] is None


def test_sole_match_requires_complete_collection_to_be_claimable():
    """
    The same sole-match ALB case as above, but with a partial
    collection run: an undiscovered sibling could be sharing this
    bill, so promotion to resource scope must not happen.
    """

    plan = {
        "service": "Amazon Elastic Load Balancing",
        "usage_type": "EU-LoadBalancerUsage",
        "region": "eu-west-1",
        "cost_context": 38.10,
        "resource_type": "load_balancer",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("alb-1")],
        collection_complete=False,
    )

    assert result["cost_attribution"] != "resource"
    assert result["claimable_resource_cost"] is None


def test_identity_matched_single_resource_is_claimable():
    plan = {
        "service": "Amazon Relational Database Service",
        "usage_type": "EU-InstanceUsage:db.t3.medium",
        "region": "eu-west-1",
        "cost_context": 120.0,
        "resource_type": "rds_instance",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("rds-1", instance_class="db.t3.medium")],
        collection_complete=True,
    )

    assert result["status"] == "current"
    assert result["cost_attribution"] == "resource"
    assert result["claimable_resource_cost"] == 120.0


def test_identity_matched_multiple_resources_is_not_claimable():
    plan = {
        "service": "Amazon Relational Database Service",
        "usage_type": "EU-InstanceUsage:db.t3.medium",
        "region": "eu-west-1",
        "cost_context": 120.0,
        "resource_type": "rds_instance",
    }

    result = reconcile_collection_plan(
        plan,
        [
            _resource("rds-1", instance_class="db.t3.medium"),
            _resource("rds-2", instance_class="db.t3.medium"),
        ],
        collection_complete=True,
    )

    assert result["cost_attribution"] == "collection_plan"
    assert result["claimable_resource_cost"] is None


def test_historical_billing_with_no_current_resource_is_never_claimable():
    plan = {
        "service": "Amazon Elastic Container Service for Kubernetes",
        "usage_type": "EU-AmazonEKS-Hours:perCluster",
        "region": "eu-west-1",
        "cost_context": 140.14,
        "resource_type": "eks_cluster",
    }

    result = reconcile_collection_plan(
        plan,
        [],
        collection_complete=True,
    )

    assert result["status"] == "historical"
    assert result["cost_attribution"] == "historical"
    assert result["claimable_resource_cost"] is None


def test_no_positive_cost_is_never_claimable():
    plan = {
        "service": "Amazon Elastic Load Balancing",
        "usage_type": "EU-LoadBalancerUsage",
        "region": "eu-west-1",
        "cost_context": 0.0,
        "resource_type": "load_balancer",
    }

    result = reconcile_collection_plan(
        plan,
        [_resource("alb-1")],
        collection_complete=True,
    )

    assert result["status"] == "no_cost"
    assert result["claimable_resource_cost"] is None
