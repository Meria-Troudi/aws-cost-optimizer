"""
Contract tests for the cost-attribution *propagation* path.

`test_reconciliation_contracts.py` verifies reconciliation computes the
right verdict in isolation. These tests verify that verdict actually
reaches the analyzer-facing billing channel.

Architecture under test
-----------------------
Billing/reconciliation belongs to the COLLECTION RESULT, never to the
resource evidence. `enrich_collection_result` attaches the verdict to
the enriched result; `billing_contexts_for_analysis` builds the
per-resource billing-context map keyed by (resource_type, resource_id)
that engines hand to AnalysisContext -- WITHOUT mutating any resource.
"""

from __future__ import annotations

from aws_cost_optimizer.collection.validation import (
    billing_contexts_for_analysis,
    enrich_collection_result,
)


def _resource(
    resource_id: str, resource_type: str = "load_balancer", **configuration
) -> dict:
    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "configuration": configuration,
        "identity": {},
    }


def _billing_key(resource) -> tuple:
    return (resource["resource_type"], resource["resource_id"])


def test_sole_resource_receives_claimable_cost_via_billing_channel():
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

    # Resources are NOT mutated with billing data.
    assert "cost_context" not in resources[0]

    contexts = billing_contexts_for_analysis([enriched])
    entry = contexts[_billing_key(resources[0])]

    assert entry["resource_cost_attributed"] is True
    assert entry["claimable_resource_cost"] == 38.10
    assert entry["billing"]["attribution_scope"] == "resource"


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
            _resource("nat-1", "nat_gateway"),
            _resource("nat-2", "nat_gateway"),
            _resource("nat-3", "nat_gateway"),
        ],
    }

    enriched = enrich_collection_result(plan, result)
    contexts = billing_contexts_for_analysis([enriched])

    for resource in enriched["resources_for_analysis"]:
        entry = contexts[_billing_key(resource)]

        assert entry["resource_cost_attributed"] is False
        assert entry["claimable_resource_cost"] is None
        # Still carried as shared evidence, not silently dropped.
        assert entry["billing"]["amount"] == 350.40
        # Not mutated onto the resource.
        assert "cost_context" not in resource


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
            _resource("rds-1", "rds_instance", instance_class="db.r6g.large"),
        ],
    }

    enriched = enrich_collection_result(plan, result)

    # The billed t3 instance is not present; the r6g resource is a
    # CURRENT_MISMATCH -- it stays analyzable for its own optimization,
    # and the t3 bill is preserved as EVIDENCE only (never attributed
    # as the r6g resource's own cost).
    assert enriched["reconciliation"]["status"] == "current_mismatch"
    assert enriched["resource_count"] == 1

    contexts = billing_contexts_for_analysis([enriched])

    key = _billing_key(_resource("rds-1", "rds_instance"))

    entry = contexts.get(key)

    assert entry is not None, "mismatch billing evidence must be preserved for analysis"

    assert entry["resource_cost_attributed"] is False
    assert entry["claimable_resource_cost"] is None
    # The bucket amount remains visible as contextual evidence.
    assert entry["billing"].get("amount") == 243.14


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
    contexts = billing_contexts_for_analysis([enriched]) or {}

    key = _billing_key(_resource("alb-1"))

    entry = contexts.get(key)

    if entry is None:
        # Partial collection may leave the resource out of analysis;
        # that is allowed as long as nothing was promoted to a claim.
        return

    assert entry["resource_cost_attributed"] is False
    assert entry["claimable_resource_cost"] is None
