"""
Recommendation domain model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_PRIORITIES = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
)

VALID_CONFIDENCE = frozenset(
    {
        "high",
        "medium",
        "low",
    }
)

VALID_STATUS = frozenset(
    {
        "requires_validation",
        "validated",
        "dismissed",
        "implemented",
    }
)


@dataclass(slots=True)
class Recommendation:

    recommendation_key: str
    title: str
    category: str

    priority: str
    confidence: str

    reason: str
    action: str

    resource_type: str | None
    scope: str

    service: str = "Unknown service"

    affected_resources: list[str] = field(
        default_factory=list
    )

    source_finding_ids: list[int] = field(
        default_factory=list
    )

    source_finding_types: list[str] = field(
        default_factory=list
    )

    source_finding_count: int = 0

    finding_id: int | None = None

    limitations: list[str] = field(
        default_factory=list
    )

    evidence: list[dict[str, Any]] = field(
        default_factory=list
    )

    financial_impact: dict[str, Any] = field(
        default_factory=dict
    )

    recommendation_variant: str | None = None

    recommendation_scope: str = "region"

    status: str = "requires_validation"

    def __post_init__(self) -> None:

        self.recommendation_key = str(
            self.recommendation_key
        ).strip()

        self.title = str(
            self.title
        ).strip()

        self.category = str(
            self.category
            or "cost_optimization"
        ).strip()

        self.service = str(
            self.service
            or "Unknown service"
        ).strip()

        self.priority = str(
            self.priority
            or "low"
        ).strip().lower()

        self.confidence = str(
            self.confidence
            or "low"
        ).strip().lower()

        self.status = str(
            self.status
            or "requires_validation"
        ).strip().lower()

        self.recommendation_scope = str(
            self.recommendation_scope
            or "region"
        ).strip().lower()

        if self.priority not in VALID_PRIORITIES:
            self.priority = "low"

        if self.confidence not in VALID_CONFIDENCE:
            self.confidence = "low"

        if self.status not in VALID_STATUS:
            self.status = "requires_validation"

        if self.recommendation_variant is not None:

            self.recommendation_variant = (
                str(
                    self.recommendation_variant
                ).strip()
                or None
            )

        self.affected_resources = [
            str(item)
            for item in self.affected_resources
            if item is not None
        ]

        self.source_finding_ids = [
            int(item)
            for item in self.source_finding_ids
            if item is not None
        ]

        self.source_finding_types = [
            str(item)
            for item in self.source_finding_types
            if item is not None
        ]

        self.source_finding_count = (
            self.source_finding_count
            or len(self.source_finding_ids)
        )

    def to_dict(self) -> dict[str, Any]:

        return {
            "recommendation_key":
                self.recommendation_key,

            "recommendation_variant":
                self.recommendation_variant,

            "recommendation_scope":
                self.recommendation_scope,

            "title":
                self.title,

            "category":
                self.category,

            "service":
                self.service,

            "priority":
                self.priority,

            "confidence":
                self.confidence,

            "status":
                self.status,

            "reason":
                self.reason,

            "action":
                self.action,

            "resource_type":
                self.resource_type,

            "scope":
                self.scope,

            "affected_resources":
                list(self.affected_resources),

            "source_finding_ids":
                list(self.source_finding_ids),

            "source_finding_types":
                list(self.source_finding_types),

            "source_finding_count":
                self.source_finding_count,

            "finding_id":
                self.finding_id,

            "limitations":
                list(self.limitations),

            "evidence":
                list(self.evidence),

            "financial_impact":
                dict(self.financial_impact),
        }

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
    ) -> "Recommendation":

        if not isinstance(value, dict):
            raise TypeError(
                "Recommendation.from_dict() expects a dictionary."
            )

        return cls(
            recommendation_key=str(
                value.get(
                    "recommendation_key",
                    "",
                )
            ),

            title=str(
                value.get(
                    "title",
                    "",
                )
            ),

            category=str(
                value.get(
                    "category",
                    "cost_optimization",
                )
            ),

            service=str(
                value.get(
                    "service",
                    "Unknown service",
                )
                or "Unknown service"
            ),

            priority=str(
                value.get(
                    "priority",
                    "low",
                )
            ),

            confidence=str(
                value.get(
                    "confidence",
                    "low",
                )
            ),

            reason=str(
                value.get(
                    "reason",
                    "",
                )
            ),

            action=str(
                value.get(
                    "action",
                    "",
                )
            ),

            resource_type=(
                str(
                    value["resource_type"]
                )
                if value.get(
                    "resource_type"
                ) is not None
                else None
            ),

            scope=str(
                value.get(
                    "scope",
                    "",
                )
            ),

            affected_resources=[
                str(item)
                for item in (
                    value.get(
                        "affected_resources",
                        [],
                    )
                    or []
                )
                if item is not None
            ],

            source_finding_ids=[
                int(item)
                for item in (
                    value.get(
                        "source_finding_ids",
                        [],
                    )
                    or []
                )
                if item is not None
            ],

            source_finding_types=[
                str(item)
                for item in (
                    value.get(
                        "source_finding_types",
                        [],
                    )
                    or []
                )
                if item is not None
            ],

            source_finding_count=int(
                value.get(
                    "source_finding_count",
                    0,
                )
                or 0
            ),

            finding_id=(
                int(value["finding_id"])
                if value.get(
                    "finding_id"
                ) is not None
                else None
            ),

            limitations=[
                str(item)
                for item in (
                    value.get(
                        "limitations",
                        [],
                    )
                    or []
                )
                if item is not None
            ],

            evidence=[
                item
                for item in (
                    value.get(
                        "evidence",
                        [],
                    )
                    or []
                )
                if isinstance(item, dict)
            ],

            financial_impact=dict(
                value.get(
                    "financial_impact",
                    {},
                )
                or {}
            ),

            recommendation_variant=(
                str(
                    value["recommendation_variant"]
                )
                if value.get(
                    "recommendation_variant"
                ) is not None
                else None
            ),

            recommendation_scope=str(
                value.get(
                    "recommendation_scope",
                    "region",
                )
            ),

            status=str(
                value.get(
                    "status",
                    "requires_validation",
                )
            ),
        )