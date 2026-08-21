"""
Structured finding evidence.

Evidence is the authoritative bridge between:

    collectors
        -> analyzers
        -> findings
        -> aggregation
        -> recommendations
        -> reporting

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:
    metrics: dict[str, Any] = field(
        default_factory=dict
    )
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


    billing: dict[str, Any] = field(
        default_factory=dict
    )
    data_quality: dict[str, Any] = field(
        default_factory=dict
    )
    def to_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "metrics": self.metrics,
            "configuration": self.configuration,
            "topology": self.topology,
            "resource": self.resource,
            "derived": self.derived,
            "billing": self.billing,
            "data_quality": self.data_quality,
        }
    def get_path(
        self,
        path: str,
        default: Any = None,
    ) -> Any:
        
        if not path:
            return default

        current: Any = self.to_dict()

        for part in path.split("."):

            if isinstance(
                current,
                dict,
            ):

                if part not in current:
                    return default

                current = current[part]
                continue

            return default

        return current
    def find_key(
        self,
        key: str,
    ) -> list[tuple[str, Any]]:

        if not key:
            return []

        result: list[
            tuple[str, Any]
        ] = []

        self._find_key_recursive(
            value=self.to_dict(),
            target=key,
            path="",
            result=result,
        )

        return result

    @classmethod
    def _find_key_recursive(
        cls,
        *,
        value: Any,
        target: str,
        path: str,
        result: list[tuple[str, Any]],
    ) -> None:

        if isinstance(
            value,
            dict,
        ):

            for key, child in value.items():

                child_path = (
                    f"{path}.{key}"
                    if path
                    else str(key)
                )

                if str(key) == target:

                    result.append(
                        (
                            child_path,
                            child,
                        )
                    )

                cls._find_key_recursive(
                    value=child,
                    target=target,
                    path=child_path,
                    result=result,
                )

        elif isinstance(
            value,
            list,
        ):

            for index, child in enumerate(
                value
            ):

                child_path = (
                    f"{path}[{index}]"
                    if path
                    else f"[{index}]"
                )

                cls._find_key_recursive(
                    value=child,
                    target=target,
                    path=child_path,
                    result=result,
                )