"""
Finding aggregation.

Raw findings are resource-level facts.

Aggregation creates reportable groups without replacing the raw
resource-level identity.

Example:

    nat-1 + nat-2 + nat-3
        -> 3 persisted raw findings
        -> 1 aggregated finding

The aggregated finding keeps references to the stable IDs of the
raw findings so the recommendation layer can resolve them to the
actual database rows.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .finding import Finding
from .financial import normalize_financial_impact
from .ranking import CONFIDENCE_RANK, SEVERITY_RANK


class FindingAggregator:

    SEVERITY_RANK = SEVERITY_RANK

    CONFIDENCE_RANK = CONFIDENCE_RANK

    VALID_SCOPES = {
        "resource",
        "region",
        "account",
        "service",
    }

    DEFAULT_SCOPE = "region"

    def __init__(
        self,
        default_scope: str = DEFAULT_SCOPE,
    ) -> None:

        self.default_scope = (
            self._normalize_scope(
                default_scope
            )
        )
    def aggregate(
        self,
        findings: list[Finding],
    ) -> list[dict[str, Any]]:

        groups: dict[
            tuple[str, str, str, str, str],
            list[Finding],
        ] = defaultdict(list)

        for finding in findings:

            if not isinstance(
                finding,
                Finding,
            ):
                continue

            scope = self._resolve_scope(
                finding
            )

            groups[
                self._group_key(
                    finding,
                    scope,
                )
            ].append(
                finding
            )

        result: list[
            dict[str, Any]
        ] = []

        for group in groups.values():

            normalized = (
                self._deduplicate_group(
                    group
                )
            )

            if not normalized:
                continue

            result.append(
                self._build_group(
                    normalized
                )
            )

        return sorted(
            result,
            key=self._sort_key,
        )
    def _resolve_scope(
        self,
        finding: Finding,
    ) -> str:

        explicit = finding.aggregation_scope

        if explicit is not None:

            return self._normalize_scope(
                explicit
            )

        return self.default_scope

    @classmethod
    def _normalize_scope(
        cls,
        value: Any,
    ) -> str:

        scope = str(
            value
            or cls.DEFAULT_SCOPE
        ).strip().lower()

        if scope not in cls.VALID_SCOPES:

            raise ValueError(
                "Invalid aggregation scope "
                f"{value!r}. Expected one of "
                f"{sorted(cls.VALID_SCOPES)}."
            )

        return scope
    def _group_key(
        self,
        finding: Finding,
        scope: str,
    ) -> tuple[str, str, str, str, str]:

        finding_key = str(
            finding.finding_key
            or finding.finding_type
            or "unknown"
        ).strip()

        resource_type = str(
            finding.resource_type
            or "unknown"
        ).strip()

        account_id = str(
            finding.account_id
            or finding.metadata.get(
                "account_id"
            )
            or "unknown"
        ).strip()

        if scope == "resource":

            scope_value = str(
                finding.resource_id
                or "unknown"
            ).strip()

        elif scope == "account":

            scope_value = "account"

        elif scope == "service":

            scope_value = self._service(
                finding
            )

        else:

            scope_value = self._region(
                finding
            )

        return (
            finding_key,
            resource_type,
            scope,
            account_id,
            scope_value,
        )
    @staticmethod
    def _deduplicate_group(
        findings: list[Finding],
    ) -> list[Finding]:

        result: list[Finding] = []

        seen: set[
            tuple[str, str, str, str]
        ] = set()

        for finding in findings:

            key = (
                str(
                    finding.account_id
                    or "unknown"
                ),

                str(
                    finding.finding_key
                    or finding.finding_type
                ),

                str(
                    finding.resource_type
                    or "unknown"
                ),

                str(
                    finding.resource_id
                    or "unknown"
                ),
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                finding
            )

        return result
    def _build_group(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:

        first = findings[0]

        scope = self._resolve_scope(
            first
        )

        resource_ids = self._unique(
            finding.resource_id
            for finding in findings
            if finding.resource_id
        )

        source_finding_stable_ids = self._unique(
            finding.finding_id
            for finding in findings
            if finding.finding_id
        )

        eligible_resource_ids = self._unique(
            finding.resource_id
            for finding in findings
            if (
                finding.recommendation_eligible
                and finding.resource_id
            )
        )

        ineligible_resource_ids = self._unique(
            finding.resource_id
            for finding in findings
            if (
                not finding.recommendation_eligible
                and finding.resource_id
            )
        )

        affected_resources = []

        for finding in findings:

            affected_resources.append(
                {
                    "resource_id":
                        finding.resource_id,

                    "resource_type":
                        finding.resource_type,

                    "severity":
                        finding.severity,

                    "confidence":
                        finding.confidence,

                    "recommendation_eligible":
                        finding.recommendation_eligible,

                    "reason":
                        finding.reason,

                    "evidence_summary":
                        list(
                            finding.evidence_summary
                        ),

                    "metadata":
                        dict(
                            finding.metadata
                        ),

                    "limitations":
                        list(
                            finding.limitations
                        ),

                    "account_id":
                        finding.account_id,

                    "region":
                        self._region(
                            finding
                        ),

                    "finding_id":
                        finding.finding_id,

                    "database_id":
                        finding.database_id,
                }
            )

        return {
            "finding_id":
                self._aggregate_id(
                    findings,
                    scope,
                ),

            "finding_key":
                (
                    first.finding_key
                    or first.finding_type
                ),

            "finding_type":
                first.finding_type,

            "source_finding_stable_ids":
                source_finding_stable_ids,

            # Will be populated by FindingEngine after raw finding
            # persistence.
            "source_finding_ids":
                [],

            "category":
                first.category,

            "title":
                self._aggregate_title(
                    findings
                ),

            "resource_type":
                first.resource_type,

            "analyzer":
                first.analyzer,

            "analyzer_version":
                self._highest_version(
                    findings
                ),

            "severity":
                self._highest(
                    findings,
                    "severity",
                    self.SEVERITY_RANK,
                ),

            "confidence":
                self._lowest(
                    findings,
                    "confidence",
                    self.CONFIDENCE_RANK,
                ),

            "status":
                self._aggregate_status(
                    findings
                ),

            "reason":
                self._aggregate_reason(
                    findings
                ),

            "resource_count":
                len(resource_ids),

            "resource_ids":
                resource_ids,

            "recommendation_eligible":
                bool(
                    eligible_resource_ids
                ),

            "recommendation_eligible_count":
                len(
                    eligible_resource_ids
                ),

            "recommendation_eligible_resource_ids":
                eligible_resource_ids,

            "recommendation_ineligible_resource_ids":
                ineligible_resource_ids,

            "evidence_summary":
                self._aggregate_evidence_summary(
                    findings
                ),

            "conditions":
                [
                    {
                        "resource_id":
                            finding.resource_id,

                        "finding_id":
                            finding.finding_id,

                        "database_id":
                            finding.database_id,

                        "conditions":
                            [
                                condition.to_dict()
                                for condition
                                in finding.conditions
                            ],
                    }
                    for finding in findings
                ],

            "evidence":
                [
                    {
                        "resource_id":
                            finding.resource_id,

                        "finding_id":
                            finding.finding_id,

                        "database_id":
                            finding.database_id,

                        "evidence":
                            finding.evidence.to_dict(),

                        "observation_period":
                            (
                                finding.observation_period.to_dict()
                                if finding.observation_period
                                else None
                            ),
                    }
                    for finding in findings
                ],

            "affected_resources":
                affected_resources,

            "resource_evidence":
                [
                    {
                        "resource_id":
                            finding.resource_id,

                        "finding_id":
                            finding.finding_id,

                        "database_id":
                            finding.database_id,

                        "evidence_summary":
                            list(
                                finding.evidence_summary
                            ),

                        "metadata":
                            dict(
                                finding.metadata
                            ),

                        "limitations":
                            list(
                                finding.limitations
                            ),

                        "billing":
                            dict(
                                finding.evidence.billing
                            ),
                    }
                    for finding in findings
                ],

            "observation_periods":
                [
                    (
                        finding.observation_period.to_dict()
                        if finding.observation_period
                        else None
                    )
                    for finding in findings
                ],

            "limitations":
                self._limitations(
                    findings
                ),

            "metadata":
                [
                    dict(
                        finding.metadata
                    )
                    for finding in findings
                ],

            "billing":
                self._aggregate_billing(
                    findings
                ),

            "impact":
                self._aggregate_impact(
                    findings
                ),

            "scope":
                self._scope(
                    first,
                    scope,
                ),

            "aggregation_scope":
                scope,

            "account_id":
                first.account_id,

            "region":
                self._region(
                    first
                ),

            "service":
                self._service(
                    first
                ),
        }
    @staticmethod
    def _aggregate_reason(
        findings: list[Finding],
    ) -> str:

        if not findings:

            return (
                "No finding details available."
            )

        resource_ids = {
            finding.resource_id
            for finding in findings
            if finding.resource_id
        }

        count = len(resource_ids)

        resource_type = (
            str(
                findings[0].resource_type
                or "resource"
            )
            .replace(
                "_",
                " ",
            )
        )

        reasons: list[str] = []

        for finding in findings:

            reason = str(
                finding.reason
                or ""
            ).strip()

            if (
                reason
                and reason not in reasons
            ):

                reasons.append(
                    reason
                )

        prefix = (
            f"{count} "
            f"{resource_type}"
            f"{'' if count == 1 else 's'} "
            "match this finding."
        )

        if len(reasons) == 1:

            return (
                f"{prefix} "
                f"{reasons[0]}"
            )

        return prefix
    @classmethod
    def _aggregate_evidence_summary(
        cls,
        findings: list[Finding],
    ) -> list[str]:

        result: list[str] = []

        for finding in findings:

            for item in (
                finding.evidence_summary
                or []
            ):

                text = str(
                    item
                ).strip()

                if not text:
                    continue

                rendered = (
                    f"{finding.resource_id}: "
                    f"{text}"
                )

                if rendered not in result:

                    result.append(
                        rendered
                    )

        return result[:100]

    @staticmethod
    def _limitations(
        findings: list[Finding],
    ) -> list[str]:

        result: list[str] = []

        for finding in findings:

            for limitation in (
                finding.limitations
                or []
            ):

                text = str(
                    limitation
                ).strip()

                if (
                    text
                    and text not in result
                ):

                    result.append(
                        text
                    )

        return result
    @staticmethod
    def _aggregate_billing(
        findings: list[Finding],
    ) -> dict[str, Any]:

        contexts = []

        for finding in findings:

            billing = (
                finding.evidence.billing
            )

            if not isinstance(
                billing,
                dict,
            ):
                continue

            contexts.append(
                dict(billing)
            )

        if not contexts:

            return {
                "available": False
            }

        resource_costs = [
            context
            for context in contexts
            if (
                context.get(
                    "attribution_scope"
                )
                == "resource"
                and
                context.get(
                    "resource_cost_attributed"
                )
                is True
            )
        ]

        collection_plan_amounts = [
            context.get(
                "amount"
            )
            for context in contexts
            if (
                context.get(
                    "attribution_scope"
                )
                == "collection_plan"
                and
                isinstance(
                    context.get(
                        "amount"
                    ),
                    (int, float),
                )
            )
        ]

        result = {
            "available": True,
            "contexts": contexts,
            "resource_cost_attributed": False,
        }

        if resource_costs:

            amount = sum(
                float(
                    context["amount"]
                )
                for context in resource_costs
                if isinstance(
                    context.get("amount"),
                    (int, float),
                )
            )

            result[
                "resource_attributed_cost"
            ] = round(
                amount,
                2,
            )

            result[
                "resource_cost_attributed"
            ] = True

        if collection_plan_amounts:

            result[
                "collection_plan_cost"
            ] = round(
                sum(
                    float(value)
                    for value
                    in collection_plan_amounts
                ),
                2,
            )

        return result
    @staticmethod
    def _aggregate_impact(
        findings: list[Finding],
    ) -> dict[str, float | str | None]:

        # Findings in one group typically share a single collection
        # plan's billing context (see AnalysisContext.billing() /
        # collection/manager.py) rather than each carrying its own
        # individually-attributed cost, so summing would
        # multiply-count the same account-level total once per
        # resource in the group. Take the whole financial_impact dict
        # from whichever finding reports the highest cost, rather
        # than maxing each field independently -- that keeps the
        # reported savings/confidence/basis consistent with the cost
        # they actually came from, instead of e.g. pairing one
        # finding's cost with a different finding's confidence.

        best_cost = None
        best_impact: dict[str, Any] | None = None

        for finding in findings:

            impact = finding.impact

            if not isinstance(
                impact,
                dict,
            ):
                continue

            finding_cost = impact.get(
                "observed_monthly_cost"
            )

            if not isinstance(
                finding_cost,
                (int, float),
            ):
                continue

            if (
                best_cost is None
                or finding_cost > best_cost
            ):

                best_cost = finding_cost
                best_impact = impact

        return normalize_financial_impact(
            best_impact
        )
    def _scope(
        self,
        finding: Finding,
        scope: str,
    ) -> str:

        if scope == "resource":

            return (
                "resource:"
                + str(
                    finding.resource_id
                    or "unknown"
                )
            )

        if scope == "account":

            return (
                "account:"
                + str(
                    finding.account_id
                    or "unknown"
                )
            )

        if scope == "service":

            return (
                "service:"
                + self._service(
                    finding
                )
            )

        return (
            "region:"
            + str(
                self._region(
                    finding
                )
                or "unknown"
            )
        )
    @staticmethod
    def _region(
        finding: Finding,
    ) -> str:

        resource = (
            finding.evidence.resource
        )

        if isinstance(
            resource,
            dict,
        ):

            value = resource.get(
                "region"
            )

            if value:
                return str(value)

        value = finding.metadata.get(
            "region"
        )

        return (
            str(value)
            if value
            else "unknown"
        )

    @staticmethod
    def _service(
        finding: Finding,
    ) -> str:

        value = finding.metadata.get(
            "service"
        )

        return (
            str(value)
            if value
            else "unknown"
        )
    def _aggregate_id(
        self,
        findings: list[Finding],
        scope: str,
    ) -> str:

        first = findings[0]

        payload = {
            "account_id":
                first.account_id,

            "finding_key":
                (
                    first.finding_key
                    or first.finding_type
                ),

            "resource_type":
                first.resource_type,

            "scope":
                self._scope(
                    first,
                    scope,
                ),
        }

        encoded = json.dumps(
            payload,
            sort_keys=True,
            default=str,
        ).encode(
            "utf-8"
        )

        digest = hashlib.sha256(
            encoded
        ).hexdigest()

        return (
            f"finding-group-{digest[:20]}"
        )
    @staticmethod
    def _aggregate_status(
        findings: list[Finding],
    ) -> str:

        statuses = {
            str(
                finding.status
            ).lower()
            for finding in findings
        }

        if statuses == {
            "informational"
        }:

            return "informational"

        return "active"
    @classmethod
    def _highest(
        cls,
        findings: list[Finding],
        field: str,
        ranking: dict[str, int],
    ) -> str:

        values = [
            str(
                getattr(
                    finding,
                    field,
                    "info",
                )
            ).lower()
            for finding in findings
        ]

        if not values:
            return "info"

        return max(
            values,
            key=lambda value:
                ranking.get(
                    value,
                    0,
                ),
        )

    @classmethod
    def _lowest(
        cls,
        findings: list[Finding],
        field: str,
        ranking: dict[str, int],
    ) -> str:

        values = [
            str(
                getattr(
                    finding,
                    field,
                    "low",
                )
            ).lower()
            for finding in findings
        ]

        if not values:
            return "low"

        return min(
            values,
            key=lambda value:
                ranking.get(
                    value,
                    0,
                ),
        )
    @staticmethod
    def _aggregate_title(
        findings: list[Finding],
    ) -> str:

        titles = {
            str(
                finding.title
                or ""
            ).strip()
            for finding in findings
            if finding.title
        }

        if len(titles) == 1:

            return next(
                iter(titles)
            )

        return (
            findings[0].title
            if findings
            else "Finding"
        )
    @staticmethod
    def _version_tuple(
        value: str,
    ) -> tuple[int, ...]:

        parts = []

        for token in str(
            value or "1.0"
        ).split("."):

            number = ""

            for char in token:

                if char.isdigit():
                    number += char
                else:
                    break

            parts.append(
                int(number)
                if number
                else 0
            )

        return tuple(parts)

    @classmethod
    def _highest_version(
        cls,
        findings: list[Finding],
    ) -> str:

        return max(
            (
                str(
                    finding.analyzer_version
                    or "1.0"
                )
                for finding in findings
            ),
            key=cls._version_tuple,
            default="1.0",
        )
    @classmethod
    def _sort_key(
        cls,
        finding: dict[str, Any],
    ):

        return (
            -cls.SEVERITY_RANK.get(
                str(
                    finding.get(
                        "severity",
                        "info",
                    )
                ).lower(),
                0,
            ),

            str(
                finding.get(
                    "title",
                    "",
                )
            ),

            str(
                finding.get(
                    "resource_type",
                    "",
                )
            ),

            str(
                finding.get(
                    "scope",
                    "",
                )
            ),
        )
    @staticmethod
    def _unique(
        values,
    ) -> list[str]:

        result: list[str] = []

        seen: set[str] = set()

        for value in values:

            if value is None:
                continue

            text = str(
                value
            ).strip()

            if (
                not text
                or text in seen
            ):
                continue

            seen.add(text)

            result.append(
                text
            )

        return result