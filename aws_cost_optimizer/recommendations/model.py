"""
Recommendation domain model.

``status`` is the deterministic engine classification (actionable /
informational / historical / insufficient_evidence).
``validation_status`` is the human lifecycle state (requires_validation /
validated / dismissed / implemented).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CONFIDENCE = frozenset({"high", "medium", "low"})
VALID_STATUS = frozenset(
    {"actionable", "informational", "historical", "insufficient_evidence"}
)
VALID_VALIDATION_STATUS = frozenset(
    {"requires_validation", "validated", "dismissed", "implemented"}
)
VALID_RECOMMENDATION_SCOPES = frozenset({"resource", "region", "service", "account"})


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
    affected_resources: list[str] = field(default_factory=list)
    source_finding_ids: list[int] = field(default_factory=list)
    source_finding_types: list[str] = field(default_factory=list)
    source_finding_count: int = 0
    finding_id: int | None = None
    limitations: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    financial_impact: dict[str, Any] = field(default_factory=dict)
    recommendation_text: str = ""
    recommendation_variant: str | None = None
    recommendation_scope: str = "resource"
    status: str = "actionable"
    validation_status: str | None = "requires_validation"
    resource: dict[str, Any] = field(default_factory=dict)
    finding: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.recommendation_key = str(self.recommendation_key).strip()
        self.title = str(self.title).strip()
        self.category = str(self.category or "cost_optimization").strip()
        self.service = str(self.service or "Unknown service").strip()
        self.priority = str(self.priority or "low").strip().lower()
        self.confidence = str(self.confidence or "low").strip().lower()
        self.status = str(self.status or "insufficient_evidence").strip().lower()
        if self.validation_status is not None:
            self.validation_status = str(self.validation_status).strip().lower()
        self.recommendation_scope = (
            str(self.recommendation_scope or "resource").strip().lower()
        )
        if self.priority not in VALID_PRIORITIES:
            self.priority = "low"
        if self.confidence not in VALID_CONFIDENCE:
            self.confidence = "low"
        if self.status not in VALID_STATUS:
            self.status = "insufficient_evidence"
        if (
            self.validation_status is not None
            and self.validation_status not in VALID_VALIDATION_STATUS
        ):
            self.validation_status = "requires_validation"
        if self.recommendation_scope not in VALID_RECOMMENDATION_SCOPES:
            raise ValueError(
                f"Invalid recommendation scope: {self.recommendation_scope!r}"
            )
        if self.recommendation_variant is not None:
            self.recommendation_variant = (
                str(self.recommendation_variant).strip() or None
            )
        self.affected_resources = [
            str(i) for i in self.affected_resources if i is not None
        ]
        self.source_finding_ids = [
            int(i) for i in self.source_finding_ids if i is not None
        ]
        self.source_finding_types = [
            str(i) for i in self.source_finding_types if i is not None
        ]
        self.source_finding_count = self.source_finding_count or len(
            self.source_finding_ids
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_key": self.recommendation_key,
            "recommendation_variant": self.recommendation_variant,
            "recommendation_scope": self.recommendation_scope,
            "title": self.title,
            "category": self.category,
            "service": self.service,
            "priority": self.priority,
            "confidence": self.confidence,
            "status": self.status,
            "validation_status": self.validation_status,
            "reason": self.reason,
            "action": self.action,
            "resource_type": self.resource_type,
            "scope": self.scope,
            "resource": dict(self.resource),
            "finding": dict(self.finding),
            "affected_resources": list(self.affected_resources),
            "source_finding_ids": list(self.source_finding_ids),
            "source_finding_types": list(self.source_finding_types),
            "source_finding_count": self.source_finding_count,
            "finding_id": self.finding_id,
            "limitations": list(self.limitations),
            "evidence": list(self.evidence),
            "financial_impact": dict(self.financial_impact),
            "recommendation_text": self.recommendation_text,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Recommendation":
        if not isinstance(value, dict):
            raise TypeError("Recommendation.from_dict() expects a dictionary.")
        return cls(
            recommendation_key=str(value.get("recommendation_key", "")),
            title=str(value.get("title", "")),
            category=str(value.get("category", "cost_optimization")),
            service=str(value.get("service", "Unknown service") or "Unknown service"),
            priority=str(value.get("priority", "low")),
            confidence=str(value.get("confidence", "low")),
            reason=str(value.get("reason", "")),
            action=str(value.get("action", "")),
            resource_type=(
                str(value["resource_type"])
                if value.get("resource_type") is not None
                else None
            ),
            scope=str(value.get("scope", "")),
            resource=dict(value.get("resource", {}) or {}),
            finding=dict(value.get("finding", {}) or {}),
            affected_resources=[
                str(i)
                for i in (value.get("affected_resources", []) or [])
                if i is not None
            ],
            source_finding_ids=[
                int(i)
                for i in (value.get("source_finding_ids", []) or [])
                if i is not None
            ],
            source_finding_types=[
                str(i)
                for i in (value.get("source_finding_types", []) or [])
                if i is not None
            ],
            source_finding_count=int(value.get("source_finding_count", 0) or 0),
            finding_id=(
                int(value["finding_id"])
                if value.get("finding_id") is not None
                else None
            ),
            limitations=[
                str(i) for i in (value.get("limitations", []) or []) if i is not None
            ],
            evidence=[
                i for i in (value.get("evidence", []) or []) if isinstance(i, dict)
            ],
            financial_impact=dict(value.get("financial_impact", {}) or {}),
            recommendation_text=str(value.get("recommendation_text", "") or ""),
            recommendation_variant=(
                str(value["recommendation_variant"])
                if value.get("recommendation_variant") is not None
                else None
            ),
            recommendation_scope=str(value.get("recommendation_scope", "resource")),
            status=str(value.get("status", "insufficient_evidence")),
            validation_status=(
                str(value["validation_status"])
                if value.get("validation_status") is not None
                else None
            ),
        )
