"""
Evidence model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:
    metrics: dict[str, Any] = field(default_factory=dict)

    configuration: dict[str, Any] = field(
        default_factory=dict
    )

    topology: dict[str, Any] = field(
        default_factory=dict
    )

    resource: dict[str, Any] = field(
        default_factory=dict
    )

    derived: dict[str, Any] = field(
        default_factory=dict
    )

    data_quality: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "metrics":
                self.metrics,

            "configuration":
                self.configuration,

            "topology":
                self.topology,

            "resource":
                self.resource,

            "derived":
                self.derived,

            "data_quality":
                self.data_quality,
        }