"""
Evidence statement used by findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class EvidenceStatement:
 

    name: str
    value: Any
    description: str
    source: list[str] = field(default_factory=list)
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "description": self.description,
            "source": self.source,
        }
@dataclass(slots=True)
class Condition:

    name: str
    operator: str
    expected: Any
    actual: Any
    passed: bool
    description: str | None = None
    evidence_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "result": self.result,
            "passed": self.passed,
            "actual": self.actual,
            "evidence_keys": self.evidence_keys,
        }
    @property
    def result(self) -> str:
        return "passed" if self.passed else "failed"