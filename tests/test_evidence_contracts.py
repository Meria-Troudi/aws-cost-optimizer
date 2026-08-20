"""
Contract tests for evidence flowing collector -> context -> finding.

These cover cross-layer key agreements, which are exactly the couplings
that break silently when one side is renamed.
"""

from __future__ import annotations

import analysis.analyzers  # noqa: F401
from analysis.context import AnalysisContext
from analysis.engine import AnalysisEngine


def _rds_resource(**overrides) -> dict:
    resource = {
        "resource_id": "db-contract-test",
        "resource_type": "rds_instance",
        "configuration": {
            "instance_class": "db.r6g.large",
            "engine": "aurora-postgresql",
            "status": "stopped",
            "multi_az": False,
            "publicly_accessible": False,
            "backup_retention_days": 7,
            "performance_insights_enabled": False,
        },
        "topology": {"status": "ok"},
        "data_quality": {"topology_available": True},
        "observations": {
            "cloudwatch": {"status": "ok", "metrics": {}},
            "cloudtrail": {
                "status": "disabled",
                "transition_count": 0,
            },
        },
        "cost_context": {
            "service": "Amazon Relational Database Service",
            "usage_type": "EU-InstanceUsage:db.t3.large",
            "attribution_scope": "collection_plan",
            "cost": {"value": 302.28, "currency": "USD"},
        },
    }
    resource.update(overrides)
    return resource


class TestDataQualityContract:
    """
    BaseCollector writes data_quality at the top level of the resource
    document. The context used to read observations["data_quality"], so
    every collector except NAT returned {} and findings shipped an empty
    data-quality block while appearing to carry evidence.
    """

    def test_reads_top_level_data_quality(self):
        context = AnalysisContext(
            resource={
                "data_quality": {"topology_available": True},
                "observations": {},
            }
        )

        assert context.data_quality() == {"topology_available": True}

    def test_nested_block_is_merged_over_top_level(self):
        context = AnalysisContext(
            resource={
                "data_quality": {"a": 1, "shared": "top"},
                "observations": {
                    "data_quality": {"shared": "nested", "b": 2}
                },
            }
        )

        assert context.data_quality() == {
            "a": 1,
            "shared": "nested",
            "b": 2,
        }

    def test_absent_data_quality_is_an_empty_dict(self):
        assert AnalysisContext(resource={}).data_quality() == {}


class TestFinancialImpactContract:
    """
    Findings must carry an observed cost and an explicit reason when
    savings cannot be quantified -- previously every financial block was
    all-None because calculate_savings() was never called.
    """

    def _stopped_finding(self, resource):
        findings = AnalysisEngine().analyze(
            [resource],
            scan_id=1,
            account_id="123456789012",
        )

        for finding in findings:
            if finding.finding_type == "rds_stopped_instance":
                return finding

        raise AssertionError("expected an rds_stopped_instance finding")

    def test_observed_cost_is_populated(self):
        finding = self._stopped_finding(_rds_resource())

        assert finding.impact["observed_monthly_cost"] == 302.28
        assert finding.impact["currency"] == "USD"

    def test_plan_level_cost_never_becomes_savings(self):
        """
        Service-level spend cannot be pinned to one resource, so savings
        must stay unquantified with a stated basis rather than silently
        reusing the observed cost.
        """

        finding = self._stopped_finding(_rds_resource())

        assert finding.impact["estimated_monthly_savings"] is None
        assert (
            finding.impact["savings_basis"]
            == "cost_not_resource_attributed"
        )

    def test_resource_attributed_cost_may_be_quantified(self):
        resource = _rds_resource()
        resource["cost_context"] = {
            **resource["cost_context"],
            "attribution_scope": "resource",
        }

        finding = self._stopped_finding(resource)

        assert finding.impact["estimated_monthly_savings"] == 302.28
        assert finding.impact["savings_basis"] == "resource_attributed"


class TestBillingServiceContract:
    """
    Analyzers must not hardcode a billing service; the engine backfills
    it from the catalog-derived cost context.
    """

    def test_service_is_backfilled_from_cost_context(self):
        findings = AnalysisEngine().analyze(
            [_rds_resource()],
            scan_id=1,
            account_id="123456789012",
        )

        assert findings

        for finding in findings:
            assert (
                finding.metadata["service"]
                == "Amazon Relational Database Service"
            )


class TestAnalyzerHealthReporting:
    """
    A broken analyzer contract must fail loudly instead of quietly
    producing nothing.
    """

    def test_analyzer_failing_on_every_resource_raises(self):
        from analysis.base import Analyzer

        class AlwaysBroken(Analyzer):
            name = "always_broken"

            def supports(self, context):
                # Wrong contract: treats the context as a dict.
                return context["resource_type"] == "rds_instance"

            def analyze(self, context):
                return []

        engine = AnalysisEngine(analyzers=[AlwaysBroken()])

        try:
            engine.analyze([_rds_resource()])
        except RuntimeError as exc:
            assert "always_broken" in str(exc)
        else:
            raise AssertionError(
                "a analyzer that fails on every resource must raise"
            )

    def test_healthy_analyzers_do_not_raise(self):
        findings = AnalysisEngine().analyze(
            [_rds_resource()],
            scan_id=1,
            account_id="123456789012",
        )

        assert findings
