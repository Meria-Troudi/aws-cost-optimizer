"""
Contract tests for the local-LLM recommendation explanation layer
(Phase D).

These never touch a real Ollama instance -- the provider is always a
stub/mock. What's under test is the surrounding contract:

    - the payload sent to the provider stays compact (no raw
      topology/CloudWatch/full-evidence keys)
    - a cached explanation short-circuits before ever calling the
      provider again
    - a provider failure degrades to ai_status="unavailable" instead
      of raising
"""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from aws_cost_optimizer.recommendations.explanation import (
    build_explanation_payload,
)
from aws_cost_optimizer.recommendations.llm.schema import (
    RecommendationExplanation,
)

from backend.database.base import Base
from backend.database.models.finding import Finding
from backend.database.models.recommendation import Recommendation
from backend.database.models.scan_run import ScanRun

import backend.api.services.recommendation_explanation_service as svc


# ======================================================================
# Payload compactness
# ======================================================================


def test_payload_never_includes_raw_topology_or_cloudwatch():

    recommendation = {
        "recommendation_key": "review_unused",
        "title": "Review idle NAT Gateway",
        "action": "review_unused",
        "category": "unused_resource",
        "priority": "medium",
        "service": "EC2 - Other",
        "resource_type": "nat_gateway",
        "scope": "nat-0123456789abcdef0",
        "financial_impact": {
            "observed_monthly_cost": None,
            "estimated_monthly_savings": None,
            "savings_basis": "cost_not_resource_attributed",
        },
    }

    finding = {
        "finding_type": "nat_gateway_idle",
        "severity": "medium",
        "confidence": "medium",
        "reason": "No traffic observed.",
        "limitations": ["Shared billing evidence."],
        "impact": {},
        "evidence": {
            "derived": {
                "traffic_observed": False,
            },
            "billing": {
                "attribution_scope": "collection_plan",
                "resource_cost_attributed": False,
                "amount": 350.40,
                "currency": "USD",
                "usage_type": "EU-NatGateway-Hours",
            },
            "topology": {
                "route_tables": ["rtb-1", "rtb-2"],
            },
            "configuration": {
                "vpc_id": "vpc-abc123",
            },
            "metrics": {
                "BytesOutToDestination": {
                    "raw_datapoints": [
                        {"timestamp": "t", "value": 0},
                    ],
                },
            },
        },
    }

    payload = build_explanation_payload(
        recommendation,
        finding,
    )

    assert "topology" not in payload["evidence"]
    assert "configuration" not in payload["evidence"]
    assert "metrics" not in payload["evidence"]
    assert "raw_datapoints" not in str(payload)

    # Allowlisted billing fields survive; the raw usage type does not.
    assert payload["evidence"]["billing"]["attribution_scope"] == (
        "collection_plan"
    )
    assert "usage_type" not in payload["evidence"]["billing"]

    assert payload["evidence"]["derived"] == {
        "traffic_observed": False,
    }


def test_payload_handles_missing_finding():

    payload = build_explanation_payload(
        {"recommendation_key": "review_unused"},
        None,
    )

    assert payload["finding"]["type"] is None
    assert payload["evidence"] == {}


# ======================================================================
# Service: cache-first + fail-safe
# ======================================================================


class _StubProvider:

    def __init__(self, *, explanation=None, error=None):
        self.model = "stub-model"
        self.calls = 0
        self._explanation = explanation
        self._error = error

    def explain(self, payload):
        self.calls += 1

        if self._error is not None:
            raise self._error

        return self._explanation


@pytest.fixture()
def db_session():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    session = session_factory()

    try:
        yield session
    finally:
        session.close()


def _seed_recommendation(session) -> int:

    scan = ScanRun(
        account_id="123456789012",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 31),
    )

    session.add(scan)
    session.flush()

    finding = Finding(
        scan_run_id=scan.id,
        resource_type="nat_gateway",
        resource_id="nat-0123456789abcdef0",
        finding_type="nat_gateway_idle",
        analyzer="nat_gateway",
        analyzer_version="1.0",
        severity="medium",
        confidence="medium",
        reason="No traffic observed.",
        recommendation_eligible=True,
    )

    session.add(finding)
    session.flush()

    recommendation = Recommendation(
        scan_run_id=scan.id,
        finding_id=finding.id,
        recommendation_key="review_unused",
        resource_type="nat_gateway",
        scope=finding.resource_id,
        title="Review idle NAT Gateway",
        action="review_unused",
        priority="medium",
        confidence="medium",
    )

    session.add(recommendation)
    session.commit()

    return recommendation.id


def test_cached_explanation_short_circuits_the_provider(
    db_session,
    monkeypatch,
):

    recommendation_id = _seed_recommendation(
        db_session
    )

    stub = _StubProvider(
        explanation=RecommendationExplanation(
            summary="s",
            why="w",
            action="a",
            confidence_note="c",
            risk="r",
        )
    )

    monkeypatch.setattr(
        svc,
        "OllamaProvider",
        lambda: stub,
    )

    service = svc.RecommendationExplanationService(
        db_session
    )

    first = service.explain(recommendation_id)

    assert stub.calls == 1
    assert first["ai_explanation"]["summary"] == "s"

    second = service.explain(recommendation_id)

    # Cached -- the provider must not be called again.
    assert stub.calls == 1
    assert second["ai_explanation"]["summary"] == "s"


def test_provider_failure_returns_unavailable_without_raising(
    db_session,
    monkeypatch,
):

    recommendation_id = _seed_recommendation(
        db_session
    )

    stub = _StubProvider(
        error=RuntimeError("connection refused")
    )

    monkeypatch.setattr(
        svc,
        "OllamaProvider",
        lambda: stub,
    )

    service = svc.RecommendationExplanationService(
        db_session
    )

    result = service.explain(recommendation_id)

    assert result["ai_status"] == "unavailable"
    assert result["ai_explanation"] is None
