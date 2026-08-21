"""
Recommendation catalog loader.

The catalog contains policy only: what kind of optimization a
recommendation represents, what evidence it requires, and what it is
forbidden to invent. It does NOT contain prose (title/reason/action
text) -- that is derived from the finding itself by the recommendation
engine, and eventually explained in natural language by the LLM layer.

It does NOT decide whether a finding is eligible.
That decision remains with the analyzer finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


VALID_RECOMMENDATION_SCOPES = frozenset(
    {
        "resource",
        "region",
        "account",
        "service",
    }
)

VALID_PRIORITIES = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
)


@dataclass(frozen=True, slots=True)
class RecommendationDefinition:

    key: str
    family: str
    action: str
    priority: str = "medium"
    recommendation_eligible: bool = True
    recommendation_scope: str = "resource"

    required_evidence: tuple[str, ...] = field(
        default_factory=tuple
    )

    never_invent: tuple[str, ...] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:

        scope = (
            str(
                self.recommendation_scope
                or "resource"
            )
            .strip()
            .lower()
        )

        if scope not in VALID_RECOMMENDATION_SCOPES:
            raise ValueError(
                f"Invalid recommendation scope "
                f"{scope!r} for {self.key!r}."
            )

        object.__setattr__(
            self,
            "recommendation_scope",
            scope,
        )

        priority = (
            str(
                self.priority
                or "medium"
            )
            .strip()
            .lower()
        )

        if priority not in VALID_PRIORITIES:
            priority = "medium"

        object.__setattr__(
            self,
            "priority",
            priority,
        )


@dataclass(frozen=True, slots=True)
class RecommendationRoute:

    recommendation_key: str


class RecommendationCatalog:

    def __init__(
        self,
        path: Path | None = None,
    ) -> None:

        self.path = (
            path
            if path is not None
            else (
                Path(__file__).resolve().parent
                / "recommendation_rules.yaml"
            )
        )

        if not self.path.exists():
            raise FileNotFoundError(
                f"Recommendation rules not found: {self.path}"
            )

        with open(
            self.path,
            "r",
            encoding="utf-8",
        ) as file:

            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError(
                "recommendation_rules.yaml must contain a mapping."
            )

        self.definitions = self._load_definitions(
            data.get(
                "recommendations",
                {},
            )
        )

        self.routes = self._load_routes(
            data.get(
                "routes",
                {},
            )
        )

        self._validate()

    @staticmethod
    def _string_tuple(
        value: Any,
    ) -> tuple[str, ...]:

        if not isinstance(
            value,
            list,
        ):
            return ()

        return tuple(
            str(item).strip()
            for item in value
            if str(item).strip()
        )

    @classmethod
    def _load_definitions(
        cls,
        value: Any,
    ) -> dict[
        str,
        RecommendationDefinition,
    ]:

        if not isinstance(
            value,
            dict,
        ):
            raise ValueError(
                "'recommendations' must be a mapping."
            )

        result: dict[
            str,
            RecommendationDefinition,
        ] = {}

        for key, raw in value.items():

            if not isinstance(
                raw,
                dict,
            ):
                raise ValueError(
                    f"Recommendation {key!r} must be a mapping."
                )

            result[
                str(key)
            ] = RecommendationDefinition(
                key=str(key),

                family=str(
                    raw.get(
                        "family",
                        "",
                    )
                ).strip(),

                action=str(
                    raw.get(
                        "action",
                        "",
                    )
                ).strip(),

                priority=str(
                    raw.get(
                        "priority",
                        "medium",
                    )
                ).strip().lower(),

                recommendation_eligible=bool(
                    raw.get(
                        "recommendation_eligible",
                        True,
                    )
                ),

                recommendation_scope=str(
                    raw.get(
                        "recommendation_scope",
                        "resource",
                    )
                ).strip().lower(),

                required_evidence=cls._string_tuple(
                    raw.get(
                        "required_evidence"
                    )
                ),

                never_invent=cls._string_tuple(
                    raw.get(
                        "never_invent"
                    )
                ),
            )

        return result

    @staticmethod
    def _load_routes(
        value: Any,
    ) -> dict[
        str,
        RecommendationRoute,
    ]:

        if not isinstance(
            value,
            dict,
        ):
            raise ValueError(
                "'routes' must be a mapping."
            )

        result: dict[
            str,
            RecommendationRoute,
        ] = {}

        for finding_type, raw in value.items():

            if not isinstance(
                raw,
                dict,
            ):
                raise ValueError(
                    f"Route {finding_type!r} must be a mapping."
                )

            result[
                str(finding_type)
            ] = RecommendationRoute(
                recommendation_key=str(
                    raw.get(
                        "recommendation_key",
                        "",
                    )
                ).strip(),
            )

        return result

    def _validate(self) -> None:

        for key, definition in self.definitions.items():

            if key != definition.key:
                raise ValueError(
                    f"Recommendation key mismatch: "
                    f"{key!r} != {definition.key!r}."
                )

            if not definition.family:
                raise ValueError(
                    f"Recommendation {key!r} has no family."
                )

            if not definition.action:
                raise ValueError(
                    f"Recommendation {key!r} has no action."
                )

            if (
                definition.recommendation_scope
                not in VALID_RECOMMENDATION_SCOPES
            ):
                raise ValueError(
                    f"Invalid scope for {key!r}: "
                    f"{definition.recommendation_scope!r}"
                )

        for finding_type, route in self.routes.items():

            if not finding_type.strip():
                raise ValueError(
                    "Finding route cannot have an empty key."
                )

            if not route.recommendation_key:
                raise ValueError(
                    f"{finding_type!r} has no recommendation_key."
                )

            definition = self.definitions.get(
                route.recommendation_key
            )

            if definition is None:
                raise ValueError(
                    f"{finding_type!r} references unknown "
                    f"recommendation "
                    f"{route.recommendation_key!r}."
                )

    def definition(
        self,
        key: str,
    ) -> RecommendationDefinition | None:

        if not key:
            return None

        return self.definitions.get(
            str(key).strip()
        )

    def route(
        self,
        finding_type: str,
    ) -> RecommendationRoute | None:

        if not finding_type:
            return None

        return self.routes.get(
            str(
                finding_type
            ).strip()
        )

    def all_definitions(
        self,
    ) -> dict[
        str,
        RecommendationDefinition,
    ]:

        return dict(
            self.definitions
        )

    def all_routes(
        self,
    ) -> dict[
        str,
        RecommendationRoute,
    ]:

        return dict(
            self.routes
        )


_catalog: RecommendationCatalog | None = None


def get_catalog() -> RecommendationCatalog:

    global _catalog

    if _catalog is None:
        _catalog = RecommendationCatalog()

    return _catalog


def validate_catalog() -> None:

    get_catalog()


def recommendation_route_for_finding(
    finding: dict[str, Any],
) -> RecommendationRoute | None:

    if not isinstance(
        finding,
        dict,
    ):
        return None

    finding_type = (
        finding.get("finding_type")
        or finding.get("finding_key")
    )

    if not finding_type:
        return None

    return get_catalog().route(
        str(finding_type).strip()
    )


def recommendation_key_for_finding(
    finding: dict[str, Any],
) -> str | None:

    route = recommendation_route_for_finding(
        finding
    )

    if route is None:
        return None

    return route.recommendation_key


def get_definition(
    recommendation_key: str,
) -> RecommendationDefinition | None:

    return get_catalog().definition(
        recommendation_key
    )


def is_supported_recommendation_key(
    recommendation_key: str,
) -> bool:

    return (
        bool(recommendation_key)
        and
        get_catalog().definition(
            recommendation_key
        )
        is not None
    )
