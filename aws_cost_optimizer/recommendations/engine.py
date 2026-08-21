"""
Deterministic recommendation engine.

Contract: exactly one recommendation per eligible raw (per-resource)
finding. No grouping across resources, no cross-finding merging, no
deduplication -- 3 idle NAT gateways must produce 3 recommendations,
never 1.
"""

from __future__ import annotations

import logging
from typing import Any

from aws_cost_optimizer.analysis.financial import (
    normalize_financial_impact,
)
from aws_cost_optimizer.analysis.ranking import (
    CONFIDENCE_RANK,
    SEVERITY_RANK,
)

from .catalog import recommendation_route_for_finding
from .policy import validate as validate_policy
from .resolver import (
    resolve_persistence_scope,
    resolve_recommendation,
)
from .scoring import score

logger = logging.getLogger(__name__)


class RecommendationEngine:

    SEVERITY_RANK = SEVERITY_RANK

    CONFIDENCE_RANK = CONFIDENCE_RANK

    def generate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        if not isinstance(
            findings,
            list,
        ):
            return []

        recommendations: list[
            dict[str, Any]
        ] = []

        for finding in findings:

            try:
                recommendation = (
                    self._build_one(
                        finding
                    )
                )

            except Exception:

                # A single malformed/incomplete finding must never
                # abort recommendation generation for the rest of
                # the scan.
                finding_type = (
                    finding.get(
                        "finding_type"
                    )
                    if isinstance(
                        finding,
                        dict,
                    )
                    else None
                )

                logger.warning(
                    "Skipping finding %r during "
                    "recommendation generation",
                    finding_type,
                    exc_info=True,
                )

                continue

            if recommendation is not None:
                recommendations.append(
                    recommendation
                )

        return sorted(
            recommendations,
            key=self._sort_key,
        )

    # --------------------------------------------------------------
    # BUILD
    # --------------------------------------------------------------

    def _build_one(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any] | None:

        if not isinstance(
            finding,
            dict,
        ):
            return None

        if finding.get(
            "recommendation_eligible"
        ) is not True:
            return None

        route = recommendation_route_for_finding(
            finding
        )

        if route is None:
            return None

        definition = resolve_recommendation(
            finding
        )

        if definition is None:
            return None

        allowed, _errors = validate_policy(
            finding,
            definition,
        )

        if not allowed:
            return None

        finding_id = self._finding_id(
            finding
        )

        if finding_id is None:
            raise RuntimeError(
                "Eligible finding has no persisted "
                "database ID."
            )

        scope = resolve_persistence_scope(
            recommendation_scope=(
                definition.recommendation_scope
            ),
            finding=finding,
        )

        priority, confidence = score(
            finding,
            definition.priority,
        )

        resource_id = finding.get(
            "resource_id"
        )

        resource_type = (
            str(
                finding.get(
                    "resource_type"
                )
                or "unknown"
            ).strip()
            or "unknown"
        )

        finding_type = str(
            finding.get("finding_type")
            or finding.get("finding_key")
            or "finding"
        )

        title = finding_type.replace(
            "_",
            " ",
        ).title()

        action = str(
            definition.action
            or "review"
        ).replace(
            "_",
            " ",
        ).title()

        reason = str(
            finding.get("reason")
            or ""
        ).strip()

        if not reason:
            reason = (
                "The recommendation is supported by "
                "the collected finding evidence."
            )

        impact = finding.get("impact")

        if not isinstance(
            impact,
            dict,
        ):
            impact = {}

        financial_impact = normalize_financial_impact(
            impact
        )

        limitations = [
            str(item).strip()
            for item in (
                finding.get("limitations")
                or []
            )
            if str(item).strip()
        ]

        evidence = [
            {
                "finding_id":
                    finding_id,

                "finding_type":
                    finding_type,

                "resource_id":
                    resource_id,

                "severity":
                    finding.get(
                        "severity"
                    ),

                "confidence":
                    finding.get(
                        "confidence"
                    ),

                "reason":
                    finding.get(
                        "reason"
                    ),

                "evidence_summary":
                    finding.get(
                        "evidence_summary",
                        [],
                    ),

                "conditions":
                    finding.get(
                        "conditions",
                        [],
                    ),

                "limitations":
                    finding.get(
                        "limitations",
                        [],
                    ),
            }
        ]

        service = str(
            finding.get("service")
            or "Unknown service"
        )

        return {
            "service":
                service,

            "recommendation_key":
                route.recommendation_key,

            "recommendation_variant":
                None,

            "recommendation_scope":
                definition.recommendation_scope,

            "resource_type":
                resource_type,

            "scope":
                scope,

            "category":
                definition.family,

            "title":
                title,

            "priority":
                priority,

            "confidence":
                confidence,

            "reason":
                reason,

            "action":
                action,

            "affected_resources":
                [resource_id]
                if resource_id
                else [],

            "source_finding_ids":
                [finding_id],

            "source_finding_types":
                [finding_type],

            "source_finding_count":
                1,

            "finding_id":
                finding_id,

            "limitations":
                limitations,

            "evidence":
                evidence,

            "financial_impact":
                financial_impact,

            "status":
                "requires_validation",

            "supporting_finding_count":
                0,
        }

    # --------------------------------------------------------------
    # HELPERS
    # --------------------------------------------------------------

    @staticmethod
    def _finding_id(
        finding: dict[str, Any],
    ) -> int | None:

        value = finding.get(
            "database_id"
        )

        try:
            number = int(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

        return (
            number
            if number > 0
            else None
        )

    @classmethod
    def _sort_key(
        cls,
        recommendation: dict[str, Any],
    ) -> tuple[int, int, str, str]:

        priority = str(
            recommendation.get(
                "priority",
                "low",
            )
        ).lower()

        confidence = str(
            recommendation.get(
                "confidence",
                "low",
            )
        ).lower()

        return (
            -cls.SEVERITY_RANK.get(
                priority,
                0,
            ),

            -cls.CONFIDENCE_RANK.get(
                confidence,
                0,
            ),

            str(
                recommendation.get(
                    "title",
                    "",
                )
            ),

            str(
                recommendation.get(
                    "scope",
                    "",
                )
            ),
        )
