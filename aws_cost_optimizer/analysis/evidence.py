"""
Structured finding evidence.

Evidence is the authoritative bridge between:

    collectors
        -> analyzers
        -> findings
        -> aggregation
        -> recommendations
        -> reporting

The evidence is structured and machine-readable.

Human-readable summaries are derived from this data and must never
be treated as the authoritative source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:

    # --------------------------------------------------------------
    # CloudWatch / operational metrics
    # --------------------------------------------------------------

    metrics: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Current AWS resource configuration
    # --------------------------------------------------------------

    configuration: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Network / resource relationships
    # --------------------------------------------------------------

    topology: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Stable resource identity
    # --------------------------------------------------------------

    resource: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Collector-derived values
    # --------------------------------------------------------------

    derived: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Billing context
    #
    # Important:
    # This may represent billing for a collection plan / usage type,
    # not necessarily a resource-specific cost.
    #
    # Therefore recommendation logic must NOT automatically assume
    # that this amount belongs exclusively to one resource.
    # --------------------------------------------------------------

    billing: dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------------
    # Data-quality information
    # --------------------------------------------------------------

    data_quality: dict[str, Any] = field(
        default_factory=dict
    )

    # ==============================================================
    # SERIALIZATION
    # ==============================================================

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

    # ==============================================================
    # PATH LOOKUP
    # ==============================================================

    def get_path(
        self,
        path: str,
        default: Any = None,
    ) -> Any:
        """
        Resolve dotted paths.

        Examples:

            metrics.RequestCount.value
            configuration.state
            topology.summary.route_count
            derived.traffic.total_bytes
            billing.amount
        """

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

    # ==============================================================
    # RECURSIVE LOOKUP
    # ==============================================================

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