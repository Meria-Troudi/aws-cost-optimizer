"""
Finding conditions and structured evidence statements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class EvidenceStatement:


    name: str
    value: Any = None
    description: str = ""

    source: list[str] = field(
        default_factory=list
    )

    evidence_keys: list[str] = field(
        default_factory=list
    )

    unit: str | None = None

    observed: bool | None = None

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "name": self.name,
            "value": self.value,
            "description": self.description,
            "source": list(self.source),
            "evidence_keys": list(
                self.evidence_keys
            ),
            "unit": self.unit,
            "observed": self.observed,
        }


@dataclass(slots=True)
class Condition:
    name: str
    operator: str
    expected: Any
    actual: Any
    passed: bool
    description: str | None = None
    evidence_keys: list[str] = field(
        default_factory=list
    )
    @property
    def result(
        self,
    ) -> str:

        return (
            "passed"
            if self.passed
            else "failed"
        )
    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "name": self.name,
            "description": self.description,
            "operator": self.operator,
            "expected": self.expected,
            "actual": self.actual,
            "result": self.result,
            "passed": self.passed,
            "evidence_keys": list(
                self.evidence_keys
            ),
        }