"""
Recommendation generation.

Flow:

    persisted/reportable finding
        -> eligibility
        -> catalog route
        -> family + variant
        -> recommendation scope
        -> grouping
        -> recommendation
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .catalog import (
    get_definition,
    get_variant,
    recommendation_route_for_finding,
)


class RecommendationEngine:

    SEVERITY_RANK = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    CONFIDENCE_RANK = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    VALID_SCOPES = frozenset(
        {
            "resource",
            "region",
            "account",
            "service",
        }
    )

    def generate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        normalized = self._normalize_findings(
            findings
        )

        groups: dict[
            tuple[
                str,
                str | None,
                str,
                str,
            ],
            list[dict[str, Any]],
        ] = defaultdict(list)

        for finding in normalized:

            # ------------------------------------------------------
            # Analyzer owns eligibility.
            # ------------------------------------------------------

            if finding.get(
                "recommendation_eligible"
            ) is not True:
                continue

            # ------------------------------------------------------
            # Recommendations must reference persisted findings.
            # ------------------------------------------------------

            if not self._has_persisted_source_id(
                finding
            ):
                raise RuntimeError(
                    "Eligible finding has no persisted database ID. "
                    "The finding must be persisted before "
                    "recommendation generation."
                )

            route = recommendation_route_for_finding(
                finding
            )

            if route is None:
                continue

            definition = get_definition(
                route.recommendation_key
            )

            if definition is None:
                continue

            resource_type = self._resource_type(
                finding
            )

            scope = self._resolve_scope(
                definition.recommendation_scope,
                finding,
            )

            if scope is None:
                continue

            groups[
                (
                    route.recommendation_key,
                    route.variant_key,
                    resource_type,
                    scope,
                )
            ].append(
                finding
            )

        recommendations: list[
            dict[str, Any]
        ] = []

        for (
            recommendation_key,
            variant_key,
            resource_type,
            scope,
        ), grouped_findings in groups.items():

            recommendation = (
                self._build_recommendation(
                    recommendation_key=recommendation_key,
                    variant_key=variant_key,
                    resource_type=resource_type,
                    scope=scope,
                    findings=grouped_findings,
                )
            )

            if recommendation is not None:
                recommendations.append(
                    recommendation
                )

        return sorted(
            recommendations,
            key=self._sort_key,
        )

    # ==================================================================
    # NORMALIZATION
    # ==================================================================

    @staticmethod
    def _normalize_findings(
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        if not isinstance(findings, list):
            return []

        result: list[dict[str, Any]] = []

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            normalized = dict(finding)

            normalized["resource_type"] = (
                str(
                    normalized.get("resource_type")
                    or "unknown"
                ).strip()
                or "unknown"
            )

            resource_ids = normalized.get(
                "resource_ids"
            )

            if not isinstance(
                resource_ids,
                list,
            ):

                resource_id = normalized.get(
                    "resource_id"
                )

                resource_ids = (
                    [resource_id]
                    if resource_id
                    else []
                )

            normalized["resource_ids"] = (
                RecommendationEngine._unique(
                    resource_ids
                )
            )

            result.append(
                normalized
            )

        return result

    # ==================================================================
    # PERSISTED FINDING CHECK
    # ==================================================================

    @staticmethod
    def _has_persisted_source_id(
        finding: dict[str, Any],
    ) -> bool:

        values = finding.get(
            "source_finding_ids"
        )

        if isinstance(values, list):
            for value in values:
                try:
                    if int(value) > 0:
                        return True
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

        value = finding.get(
            "database_id"
        )

        try:
            return int(value) > 0
        except (
            TypeError,
            ValueError,
        ):
            return False

    # ==================================================================
    # SCOPE
    # ==================================================================

    def _resolve_scope(
        self,
        scope_type: str,
        finding: dict[str, Any],
    ) -> str | None:

        scope = str(
            scope_type or "region"
        ).strip().lower()

        if scope not in self.VALID_SCOPES:
            raise ValueError(
                f"Invalid recommendation scope: {scope!r}"
            )

        if scope == "resource":

            resource_id = finding.get(
                "resource_id"
            )

            resource_ids = finding.get(
                "resource_ids"
            )

            if not resource_id and (
                isinstance(resource_ids, list)
                and len(resource_ids) == 1
            ):
                resource_id = resource_ids[0]

            if not resource_id:
                return None

            return f"resource:{resource_id}"

        if scope == "account":

            account_id = (
                finding.get("account_id")
                or self._first_metadata_value(
                    finding,
                    "account_id",
                )
            )

            if not account_id:
                return None

            return f"account:{account_id}"

        if scope == "service":

            service = (
                finding.get("service")
                or self._first_metadata_value(
                    finding,
                    "service",
                )
            )

            if not service:
                return None

            return f"service:{service}"

        region = (
            finding.get("region")
            or self._first_metadata_value(
                finding,
                "region",
            )
            or self._extract_region(
                finding
            )
        )

        if not region:
            return None

        return f"region:{region}"

    # ==================================================================
    # BUILD
    # ==================================================================

    def _build_recommendation(
        self,
        *,
        recommendation_key: str,
        variant_key: str | None,
        resource_type: str,
        scope: str,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any] | None:

        definition = get_definition(
            recommendation_key
        )

        if definition is None or not findings:
            return None

        variant = get_variant(
            recommendation_key,
            variant_key,
        )

        affected_resources = (
            self._unique_resource_ids(
                findings
            )
        )

        if not affected_resources:
            return None

        source_finding_ids = (
            self._unique_finding_ids(
                findings
            )
        )

        if not source_finding_ids:
            raise RuntimeError(
                "Recommendation has no persisted source findings: "
                f"{recommendation_key}:"
                f"{variant_key or 'default'}"
            )

        source_finding_types = self._unique(
            (
                finding.get("finding_type")
                or finding.get("finding_key")
                for finding in findings
            )
        )

        title = (
            variant.title
            if variant is not None
            else definition.title
        )

        action = (
            variant.action
            if variant is not None
            else definition.default_action
        )

        reason = self._render_reason(
            (
                variant.reason
                if variant is not None
                else ""
            ),
            count=len(affected_resources),
        )

        if not reason:
            reason = (
                "Recommendation is supported by "
                "the collected finding evidence."
            )

        return {
            "recommendation_key":
                recommendation_key,

            "recommendation_variant":
                variant_key,

            "recommendation_scope":
                definition.recommendation_scope,

            "resource_type":
                resource_type,

            "scope":
                scope,

            "category":
                definition.category,

            "title":
                title,

            "priority":
                self._highest(
                    findings,
                    "severity",
                    self.SEVERITY_RANK,
                ),

            "confidence":
                self._highest(
                    findings,
                    "confidence",
                    self.CONFIDENCE_RANK,
                ),

            "reason":
                reason,

            "action":
                action,

            "affected_resources":
                affected_resources,

            "source_finding_ids":
                source_finding_ids,

            "source_finding_types":
                source_finding_types,

            "source_finding_count":
                len(source_finding_ids),

            "finding_id":
                source_finding_ids[0],

            "limitations":
                self._limitations(
                    findings
                ),

            "evidence":
                self._build_evidence(
                    findings
                ),

            "financial_impact":
                self._build_financial_impact(
                    findings
                ),

            "status":
                "requires_validation",
        }

    # ==================================================================
    # FINANCIAL IMPACT
    # ==================================================================

    @staticmethod
    def _build_financial_impact(
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:

        impacts: list[dict[str, Any]] = []

        for finding in findings:

            impact = (
                finding.get("impact")
                or finding.get("financial_impact")
            )

            if not isinstance(
                impact,
                dict,
            ) or not impact:
                continue

            impacts.append(
                {
                    "finding_id":
                        finding.get("database_id")
                        or finding.get("finding_id"),

                    "resource_ids":
                        finding.get(
                            "resource_ids",
                            [],
                        ),

                    "impact":
                        dict(impact),
                }
            )

        if not impacts:
            return {}

        if len(impacts) == 1:
            return dict(
                impacts[0]["impact"]
            )

        return {
            "items": impacts
        }

    # ==================================================================
    # EVIDENCE
    # ==================================================================

    @staticmethod
    def _build_evidence(
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        result = []

        for finding in findings:

            result.append(
                {
                    "finding_id":
                        finding.get(
                            "database_id"
                        )
                        or finding.get(
                            "finding_id"
                        ),

                    "finding_type":
                        finding.get(
                            "finding_type"
                        ),

                    "resource_type":
                        finding.get(
                            "resource_type"
                        ),

                    "resource_ids":
                        finding.get(
                            "resource_ids",
                            [],
                        ),

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

                    "limitations":
                        finding.get(
                            "limitations",
                            [],
                        ),
                }
            )

        return result

    # ==================================================================
    # LIMITATIONS
    # ==================================================================

    @staticmethod
    def _limitations(
        findings: list[dict[str, Any]],
    ) -> list[str]:

        result: list[str] = []

        for finding in findings:

            limitations = finding.get(
                "limitations"
            )

            if not isinstance(
                limitations,
                list,
            ):
                continue

            for limitation in limitations:

                text = str(
                    limitation
                ).strip()

                if text and text not in result:
                    result.append(text)

        return result

    # ==================================================================
    # METADATA
    # ==================================================================

    @staticmethod
    def _metadata_items(
        finding: dict[str, Any],
    ) -> list[dict[str, Any]]:

        value = finding.get(
            "metadata"
        )

        if isinstance(value, dict):
            return [value]

        if isinstance(value, list):
            return [
                item
                for item in value
                if isinstance(item, dict)
            ]

        return []

    def _first_metadata_value(
        self,
        finding: dict[str, Any],
        key: str,
    ) -> Any:

        for item in self._metadata_items(
            finding
        ):

            value = item.get(
                key
            )

            if value is not None:
                return value

        return None

    # ==================================================================
    # REGION
    # ==================================================================

    def _extract_region(
        self,
        finding: dict[str, Any],
    ) -> str | None:

        evidence = finding.get(
            "evidence"
        )

        if isinstance(
            evidence,
            dict,
        ):

            region = self._region_from_evidence(
                evidence
            )

            if region:
                return region

        if isinstance(
            evidence,
            list,
        ):

            for item in evidence:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                nested = item.get(
                    "evidence",
                    item,
                )

                if not isinstance(
                    nested,
                    dict,
                ):
                    continue

                region = self._region_from_evidence(
                    nested
                )

                if region:
                    return region

        return None

    @staticmethod
    def _region_from_evidence(
        evidence: dict[str, Any],
    ) -> str | None:

        resource = evidence.get(
            "resource"
        )

        if isinstance(
            resource,
            dict,
        ):

            region = resource.get(
                "region"
            )

            if region:
                return str(region)

        items = evidence.get(
            "items"
        )

        if isinstance(
            items,
            list,
        ):

            for item in items:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                resource = item.get(
                    "resource"
                )

                if isinstance(
                    resource,
                    dict,
                ):

                    region = resource.get(
                        "region"
                    )

                    if region:
                        return str(region)

        return None

    # ==================================================================
    # RESOURCES
    # ==================================================================

    @staticmethod
    def _resource_type(
        finding: dict[str, Any],
    ) -> str:

        return (
            str(
                finding.get(
                    "resource_type"
                )
                or "unknown"
            ).strip()
            or "unknown"
        )

    @staticmethod
    def _unique_resource_ids(
        findings: list[dict[str, Any]],
    ) -> list[str]:

        result: list[str] = []
        seen: set[str] = set()

        for finding in findings:

            values = finding.get(
                "resource_ids"
            )

            if not isinstance(
                values,
                list,
            ) or not values:

                value = finding.get(
                    "resource_id"
                )

                values = (
                    [value]
                    if value
                    else []
                )

            for value in values:

                if value is None:
                    continue

                text = str(
                    value
                ).strip()

                if not text or text in seen:
                    continue

                seen.add(text)
                result.append(text)

        return result

    # ==================================================================
    # SOURCE FINDING IDS
    # ==================================================================
    @staticmethod
    def _unique_finding_ids(
        findings: list[dict[str, Any]],
    ) -> list[int]:

        result: list[int] = []
        seen: set[int] = set()

        for finding in findings:

            # ------------------------------------------------------
            # Preferred source:
            #
            # Aggregated findings contain the actual persisted
            # raw Finding database IDs here.
            # ------------------------------------------------------

            source_ids = finding.get(
                "source_finding_ids"
            )

            if isinstance(
                source_ids,
                list,
            ):

                for candidate in source_ids:

                    if candidate is None:
                        continue

                    try:
                        number = int(
                            candidate
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        continue

                    if number in seen:
                        continue

                    seen.add(
                        number
                    )

                    result.append(
                        number
                    )

            # ------------------------------------------------------
            # Backward compatibility for single-finding dictionaries.
            # ------------------------------------------------------

            candidates = (
                finding.get(
                    "database_id"
                ),
                finding.get(
                    "finding_id"
                ),
            )

            for candidate in candidates:

                if candidate is None:
                    continue

                try:
                    number = int(
                        candidate
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

                if number in seen:
                    continue

                seen.add(
                    number
                )

                result.append(
                    number
                )

                # Only use fallback identity when explicit
                # source_finding_ids were not available.
                break

        return result

    # ==================================================================
    # FORMAT
    # ==================================================================

    @staticmethod
    def _render_reason(
        template: str,
        *,
        count: int,
    ) -> str:

        if not template:
            return ""

        plural = "" if count == 1 else "s"

        try:
            return template.format(
                count=count,
                plural=plural,
                is_are="is" if count == 1 else "are",
                has_have="has" if count == 1 else "have",
            )
        except (
            KeyError,
            ValueError,
        ):
            return template

    @staticmethod
    def _unique(values) -> list[str]:

        result: list[str] = []
        seen: set[str] = set()

        for value in values:

            if value is None:
                continue

            text = str(
                value
            ).strip()

            if not text or text in seen:
                continue

            seen.add(text)
            result.append(text)

        return result

    # ==================================================================
    # RANKING
    # ==================================================================

    @classmethod
    def _highest(
        cls,
        findings: list[dict[str, Any]],
        field: str,
        ranking: dict[str, int],
    ) -> str:

        best = "low"
        best_rank = -1

        for finding in findings:

            value = str(
                finding.get(
                    field,
                    "low",
                )
            ).strip().lower()

            rank = ranking.get(
                value,
                0,
            )

            if rank > best_rank:
                best = value
                best_rank = rank

        return best

    # ==================================================================
    # SORT
    # ==================================================================

    @classmethod
    def _sort_key(
        cls,
        recommendation: dict[str, Any],
    ) -> tuple[int, str, str, str]:

        priority = str(
            recommendation.get(
                "priority",
                "low",
            )
        ).lower()

        return (
            -cls.SEVERITY_RANK.get(
                priority,
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
                    "resource_type",
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