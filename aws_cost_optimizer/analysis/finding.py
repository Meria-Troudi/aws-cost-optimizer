"""
Core finding models.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from .condition import EvidenceStatement
from .evidence import Evidence


@dataclass(slots=True)
class ObservationPeriod:

    start: str | None

    end: str | None

    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "duration_seconds": self.duration_seconds,
        }


@dataclass(slots=True)
class Finding:

    finding_type: str

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

    finding_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    recommendation_eligible: bool = False

    def to_dict(self) -> dict[str, Any]:

        return {
            "finding_id": self.finding_id,

            "finding_type": self.finding_type,

            "resource_type": self.resource_type,

            "resource_id": self.resource_id,

            "analyzer": self.analyzer,

            "analyzer_version": self.analyzer_version,

            "severity": self.severity,

            "confidence": self.confidence,

            "reason": self.reason,

            "conditions": [
                condition.to_dict()
                for condition in self.conditions
            ],

            "evidence": self.evidence.to_dict(),

            "observation_period": (
                self.observation_period.to_dict()
                if self.observation_period
                else None
            ),

            "recommendation_eligible":
                self.recommendation_eligible,

            "limitations":
                self.limitations,

            "metadata":
                self.metadata,
        }