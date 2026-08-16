"""
Optimization pipeline.

resources
    -> findings
    -> persisted findings
    -> recommendations
    -> persisted recommendations
"""

from __future__ import annotations

from typing import Any

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
        resources: list[dict[str, Any]],
        enriched_results: list[dict[str, Any]] | None = None,
        collection_plans: list[dict[str, Any]] | None = None,
        pre_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:

        # Reconciliation is handled upstream.
        _ = collection_plans

        if scan is None:
            raise ValueError(
                "scan is required."
            )

        if not isinstance(
            resources,
            list,
        ):
            raise TypeError(
                "resources must be a list."
            )

        try:

            findings = (
                self.finding_engine.evaluate_and_persist(
                    db=db,
                    scan=scan,
                    resources=resources,
                    enriched_results=enriched_results,
                    pre_findings=pre_findings,
                )
            )

            recommendations = (
                self.recommendation_engine.generate(
                    findings
                )
            )

            saved = (
                self._save_recommendations(
                    db=db,
                    scan=scan,
                    recommendations=recommendations,
                )
                if recommendations
                else []
            )

            if len(saved) != len(
                recommendations
            ):
                raise RuntimeError(
                    "Recommendation persistence count mismatch: "
                    f"{len(recommendations)} generated, "
                    f"{len(saved)} persisted."
                )

            db.commit()

            return {
                "scan_run_id":
                    scan.id,

                "findings":
                    findings,

                "finding_count":
                    len(findings),

                "recommendations":
                    recommendations,

                "recommendation_count":
                    len(recommendations),

                "saved_recommendation_count":
                    len(saved),
            }

        except Exception:
            db.rollback()
            raise

    @staticmethod
    def _save_recommendations(
        db: Session,
        scan,
        recommendations: list[
            dict[str, Any]
        ],
    ) -> list[Any]:

        try:

            from backend.database.repository.recommendation_repository import (
                save_recommendations,
            )

        except ImportError as exc:

            raise RuntimeError(
                "Recommendation repository is not available."
            ) from exc

        saved = save_recommendations(
            db=db,
            scan_run_id=scan.id,
            recommendations=recommendations,
        )

        if saved is None:
            return []

        if isinstance(
            saved,
            list,
        ):
            return saved

        return [saved]