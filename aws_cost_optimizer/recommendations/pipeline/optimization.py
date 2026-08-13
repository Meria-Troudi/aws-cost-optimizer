"""
Optimization pipeline.

"""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.orm import Session

from aws_cost_optimizer.analysis.finding_engine import (
    FindingEngine,
)
from aws_cost_optimizer.recommendations.engine import (
    RecommendationEngine,
)


class OptimizationPipeline:

    def __init__(
        self,
        analyzers: list | None = None,
    ) -> None:

        self.finding_engine = FindingEngine(
            analyzers=analyzers
        )

        self.recommendation_engine = (
            RecommendationEngine()
        )

    def run(
        self,
        db: Session,
        scan,
        resources: List[Dict[str, Any]],
        collection_plans: List[Dict[str, Any]] | None = None,
        pre_findings: List[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:

        findings = (
            self.finding_engine
            .evaluate_and_persist(
                db=db,
                scan=scan,
                resources=resources,
                collection_plans=collection_plans,
            )
        )

        if pre_findings:
            pre_saved = self._save_pre_findings(
                db=db,
                scan=scan,
                findings=pre_findings,
            )
            self._attach_database_ids(
                findings=pre_findings,
                saved=pre_saved,
            )
            findings.extend(pre_findings)

        recommendations = (
            self.recommendation_engine
            .generate(
                findings
            )
        )

        if recommendations:

            self._save_recommendations(
                db=db,
                scan=scan,
                recommendations=recommendations,
            )

        db.commit()

        return {
            "scan_run_id": scan.id,

            "findings": findings,

            "finding_count": len(findings),

            "recommendations": recommendations,

            "recommendation_count": (
                len(recommendations)
            ),
        }

    @staticmethod
    def _save_pre_findings(
        db: Session,
        scan,
        findings: List[Dict[str, Any]],
    ) -> List[Any]:

        if not findings:
            return []

        try:

            from backend.database.repository.finding_repository import (
                save_findings,
            )

        except ImportError as exc:
            raise RuntimeError(
                "Finding repository is not available."
            ) from exc

        return save_findings(
            db=db,
            scan_run_id=scan.id,
            findings=findings,
        )

    @staticmethod
    def _attach_database_ids(
        findings: List[Dict[str, Any]],
        saved,
    ) -> None:
        for finding, obj in zip(findings, saved):
            if hasattr(obj, "id"):
                finding["database_id"] = obj.id

    @staticmethod
    def _save_recommendations(
        db: Session,
        scan,
        recommendations: List[Dict[str, Any]],
    ) -> None:

        try:

            from backend.database.repository.recommendation_repository import (
                save_recommendations,
            )

        except ImportError as exc:
            raise RuntimeError(
                "Recommendation repository is not available."
            ) from exc

        save_recommendations(
            db=db,
            scan_run_id=scan.id,
            recommendations=recommendations,
        )
