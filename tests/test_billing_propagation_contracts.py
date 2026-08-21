"""
Contract tests for the cost-attribution *propagation* path.

`test_reconciliation_contracts.py` verifies reconciliation computes the
right verdict in isolation. These tests verify that verdict actually
reaches the resource that goes to analyzers -- through
`collection/validation.py::enrich_collection_result`, the function that
connects reconciliation's per-plan verdict to each resource's own
`cost_context`. Before this fix, `collection/manager.py` stamped every
resource with a hardcoded `attribution_scope: "collection_plan"` before
reconciliation ever ran, and nothing overwrote it afterward -- so no
finding could ever quantify savings regardless of what reconciliation
decided.
"""

from __future__ import annotations

from collection.validation import enrich_collection_result


def _resource(resource_id: str, **configuration) -> dict:
    return {
        "resource_id": resource_id,
        "configuration": configuration,
        "identity": {},
        "cost_context": {},
    }


def test_sole_resource_receives_claimable_cost_on_its_own_cost_context():
    plan = {
        "service": "Amazon Elastic Load Balancing",
        "usage_type": "EU-LoadBalancerUsage",
        "region": "eu-west-1",
        "cost_context": 38.10,
        "resource_type": "load_balancer",
    }

    result = {
        "status": "completed",
        "resource_data": [_resource("alb-1")],
    }

    enriched = enrich_collection_result(plan, result)

    resources = enriched["resources_for_analysis"]
    assert len(resources) == 1

    cost_context = resources[0]["cost_context"]
    assert cost_context["attribution_scope"] == "resource"
    assert cost_context["claimable_resource_cost"] == 38.10


def test_shared_resources_never_receive_a_claimed_cost():
    plan = {
        "service": "EC2 - Other",
        "usage_type": "EU-NatGateway-Hours",
        "region": "eu-west-1",
        "cost_context": 350.40,
        "resource_type": "nat_gateway",
    }

    result = {
        "status": "completed",
        "resource_data": [
            _resource("nat-1"),
            _resource("nat-2"),
            _resource("nat-3"),
        ],
    }

    enriched = enrich_collection_result(plan, result)

    for resource in enriched["resources_for_analysis"]:
        cost_context = resource["cost_context"]
        assert cost_context["attribution_scope"] != "resource"
        assert cost_context["claimable_resource_cost"] is None
        # Still carried as shared evidence, not silently dropped.
        assert cost_context["amount"] == 350.40


def test_mismatched_identity_resource_never_receives_the_historical_bill():
    plan = {
        "service": "Amazon Relational Database Service",
        "usage_type": "EU-InstanceUsage:db.t3.large",
        "region": "eu-west-1",
        "cost_context": 243.14,
        "resource_type": "rds_instance",
    }

    result = {
        "status": "completed",
        "resource_data": [
            _resource("rds-1", instance_class="db.r6g.large"),
        ],
    }

    enriched = enrich_collection_result(plan, result)

    resources = enriched["resources_for_analysis"]
    assert len(resources) == 1

    cost_context = resources[0]["cost_context"]
    assert cost_context["attribution_scope"] != "resource"
    assert cost_context["claimable_resource_cost"] is None


def test_incomplete_collection_never_promotes_a_sole_match_to_claimable():
    plan = {
        "service": "Amazon Elastic Load Balancing",
        "usage_type": "EU-LoadBalancerUsage",
        "region": "eu-west-1",
        "cost_context": 38.10,
        "resource_type": "load_balancer",
    }

    result = {
        "status": "partial",
        "resource_data": [_resource("alb-1")],
    }

    enriched = enrich_collection_result(plan, result)

    for resource in enriched.get("resources_for_analysis") or []:
        cost_context = resource["cost_context"]
        assert cost_context.get("attribution_scope") != "resource"
        assert cost_context.get("claimable_resource_cost") is None
