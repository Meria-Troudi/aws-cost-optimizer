"""
Finding evaluation engine.
"""

from __future__ import annotations

from typing import Any

from .aggregation import FindingAggregator
from .billing_consistency import evaluate_rds_billing_plans
from .engine import AnalysisEngine


class FindingEngine:

    def __init__(self, analyzers: list | None = None) -> None:
        self.analysis_engine = AnalysisEngine(analyzers=analyzers)
        self.aggregator = FindingAggregator()

    def evaluate(
        self,
        resources: list[dict[str, Any]],
        *,
        scan_id: int | str | None = None,
        account_id: str | None = None,
        collection_plans: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:

        findings = self.analysis_engine.analyze(
            resources,
            scan_id=scan_id,
            account_id=account_id,
        )

        aggregated = self.aggregator.aggregate(findings)

        if collection_plans:
            aggregated.extend(
                evaluate_rds_billing_plans(
                    collection_plans,
                    resources,
                )
            )

        return aggregated

    def evaluate_and_persist(
        self,
        db,
        scan,
        resources: list[dict[str, Any]],
        collection_plans: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:

        findings = self.evaluate(
            resources,
            scan_id=scan.id,
            account_id=getattr(scan, "account_id", None),
            collection_plans=collection_plans,
        )

        saved = self._persist(
            db=db,
            scan=scan,
            findings=findings,
        )

        if saved:
            self._attach_database_ids(
                findings=findings,
                saved=saved,
            )

        return findings

    @staticmethod
    def _persist(db, scan, findings: list[dict[str, Any]]):
        if not findings:
            return []

        try:
            from backend.database.repository.finding_repository import save_findings
        except ImportError as exc:
            raise RuntimeError("Finding repository is not available.") from exc

        return save_findings(
            db=db,
            scan_run_id=scan.id,
            findings=findings,
        )

    @staticmethod
    def _attach_database_ids(findings: list[dict[str, Any]], saved) -> None:
        for finding, obj in zip(findings, saved):
            if hasattr(obj, "id"):
                finding["database_id"] = obj.id