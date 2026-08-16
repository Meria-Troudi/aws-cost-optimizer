"""
Core finding models.

Raw finding:
    one resource + one detected condition

Aggregated finding:
    produced later by FindingAggregator
"""

from __future__ import annotations

import hashlib
import json

from dataclasses import dataclass, field
from typing import Any

from .condition import EvidenceStatement
from .evidence import Evidence


@dataclass(slots=True)
class ObservationPeriod:

    start: str | None
    end: str | None
    duration_seconds: float | None = None

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "start": self.start,
            "end": self.end,
            "duration_seconds":
                self.duration_seconds,
        }

@dataclass(slots=True)
class Finding:

    finding_type: str
    title: str

    resource_type: str
    resource_id: str

    analyzer: str
    analyzer_version: str

    severity: str
    confidence: str

    reason: str

    conditions: list[EvidenceStatement]

    evidence: Evidence

    observation_period: ObservationPeriod | None

    limitations: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    finding_id: str | None = None

    database_id: int | None = None

    recommendation_eligible: bool = False

    aggregation_scope: str | None = None

    category: str = "optimization"

    status: str = "active"

    finding_key: str | None = None

    evidence_summary: list[str] = field(
        default_factory=list
    )

    impact: dict[str, Any] = field(
        default_factory=dict
    )

    account_id: str | None = None

    def __post_init__(self) -> None:

        self.severity = str(
            self.severity or "info"
        ).lower()

        self.confidence = str(
            self.confidence or "medium"
        ).lower()

        self.category = str(
            self.category or "optimization"
        ).lower()

        self.status = str(
            self.status or "active"
        ).lower()

        if self.aggregation_scope is not None:

            self.aggregation_scope = str(
                self.aggregation_scope
            ).strip().lower() or None

        self.resource_id = str(
            self.resource_id
            or "unknown"
        )

        if not self.account_id:

            resource_evidence = (
                self.evidence.resource
                if isinstance(
                    self.evidence.resource,
                    dict,
                )
                else {}
            )

            account_id = (
                resource_evidence.get(
                    "account_id"
                )
            )

            if account_id:

                self.account_id = str(
                    account_id
                )

        if not self.finding_key:

            self.finding_key = (
                self.build_finding_key()
            )

        if not self.finding_id:

            self.finding_id = (
                self.build_stable_id()
            )

        if not self.evidence_summary:

            self.evidence_summary = (
                self.build_evidence_summary()
            )

    def build_finding_key(
        self,
    ) -> str:

        return (
            f"{self.category}:"
            f"{self.finding_type}:"
            f"{self.resource_type}"
        )

    def build_stable_id(
        self,
    ) -> str:

        # Raw identity is always resource-specific.
        payload = {
            "finding_key":
                (
                    self.finding_key
                    or self.build_finding_key()
                ),

            "resource_type":
                self.resource_type,

            "resource_id":
                self.resource_id,

            "region":
                self._region(),

            "account_id":
                self.account_id,
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
            f"finding-{digest[:20]}"
        )

    def _region(
        self,
    ) -> str | None:

        resource = self.evidence.resource

        if isinstance(
            resource,
            dict,
        ):

            value = resource.get(
                "region"
            )

            if value:
                return str(value)

        value = self.metadata.get(
            "region"
        )

        return (
            str(value)
            if value
            else None
        )

    def build_evidence_summary(
        self,
    ) -> list[str]:

        result = []

        for statement in (
            self.conditions or []
        ):

            if not isinstance(
                statement,
                EvidenceStatement,
            ):
                continue

            rendered = (
                self._render_statement(
                    statement
                )
            )

            if (
                rendered
                and rendered not in result
            ):

                result.append(
                    rendered
                )

        return result[:20]

    def _render_statement(
        self,
        statement: EvidenceStatement,
    ) -> str:

        for path in (
            statement.evidence_keys
            or []
        ):

            value = self.evidence.get_path(
                path
            )

            if value is None:
                continue

            return self._format_fact(
                statement.name,
                value,
                statement.unit,
            )

        if (
            statement.value is not None
            and statement.value != ""
        ):

            return self._format_fact(
                statement.name,
                statement.value,
                statement.unit,
            )

        matches = self.evidence.find_key(
            statement.name
        )

        if matches:

            _, value = matches[0]

            return self._format_fact(
                statement.name,
                value,
                statement.unit,
            )

        return (
            statement.description
            or ""
        ).strip()

    @staticmethod
    def _format_fact(
        name: str,
        value: Any,
        unit: str | None = None,
    ) -> str:

        label = str(
            name or "evidence"
        ).replace(
            "_",
            " ",
        ).strip()

        rendered = (
            Finding._format_value(
                value
            )
        )

        suffix = (
            f" {unit}"
            if unit
            else ""
        )

        return (
            f"{label}: "
            f"{rendered}"
            f"{suffix}"
        )

    @staticmethod
    def _format_value(
        value: Any,
    ) -> str:

        if value is None:
            return "unknown"

        if isinstance(
            value,
            bool,
        ):

            return (
                "true"
                if value
                else "false"
            )

        if isinstance(
            value,
            float,
        ):

            if value.is_integer():
                return f"{int(value):,}"

            return f"{value:,.4f}"

        if isinstance(
            value,
            int,
        ):

            return f"{value:,}"

        if isinstance(
            value,
            dict,
        ):

            return (
                "{"
                + ", ".join(
                    f"{key}="
                    f"{Finding._format_value(child)}"
                    for key, child in value.items()
                    if child is not None
                )
                + "}"
            )

        if isinstance(
            value,
            list,
        ):

            return (
                "["
                + ", ".join(
                    Finding._format_value(
                        item
                    )
                    for item in value
                )
                + "]"
            )

        return str(value)

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "finding_id":
                self.finding_id,

            "finding_key":
                self.finding_key,

            "finding_type":
                self.finding_type,

            "category":
                self.category,

            "title":
                self.title,

            "resource_type":
                self.resource_type,

            "resource_id":
                self.resource_id,

            "analyzer":
                self.analyzer,

            "analyzer_version":
                self.analyzer_version,

            "severity":
                self.severity,

            "confidence":
                self.confidence,

            "status":
                self.status,

            "reason":
                self.reason,

            "conditions":
                [
                    condition.to_dict()
                    for condition
                    in self.conditions
                ],

            "evidence":
                self.evidence.to_dict(),

            "evidence_summary":
                list(
                    self.evidence_summary
                ),

            "observation_period":
                (
                    self.observation_period.to_dict()
                    if self.observation_period
                    else None
                ),

            "impact":
                dict(
                    self.impact
                ),

            "recommendation_eligible":
                self.recommendation_eligible,

            "aggregation_scope":
                self.aggregation_scope,

            "limitations":
                list(
                    self.limitations
                ),

            "metadata":
                dict(
                    self.metadata
                ),

            "account_id":
                self.account_id,

            "region":
                self._region(),
            "database_id":
    self.database_id,
        }