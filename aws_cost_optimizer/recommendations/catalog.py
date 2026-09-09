"""
Recommendation catalog loader.

Declarative source for recommendation intent, evidence requirements,
financial basis, output constraints, and never-invent rules.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

VALID_RECOMMENDATION_SCOPES = frozenset({"resource", "region", "account", "service"})
VALID_PRIORITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_FINANCIAL_BASES = frozenset(
    {
        "resource_attributed_cost",
        "collection_plan_cost",
        "service_cost",
        "historical_cost",
        "unavailable",
    }
)


@dataclass(frozen=True, slots=True)
class RecommendationDefinition:
    """Declarative recommendation definition loaded from YAML."""

    key: str
    family: str
    action: str
    display_action: str = ""
    priority: str = "medium"
    recommendation_eligible: bool = True
    recommendation_scope: str = "resource"
    required_evidence: tuple[str, ...] = field(default_factory=tuple)
    safety_evidence: tuple[str, ...] = field(default_factory=tuple)
    optional_evidence: tuple[str, ...] = field(default_factory=tuple)
    never_invent: tuple[str, ...] = field(default_factory=tuple)
    output_constraints: dict[str, Any] = field(default_factory=dict)
    financial_basis: dict[str, Any] = field(default_factory=dict)
    procedure: dict[str, Any] = field(default_factory=dict)
    title_template: str = ""

    def __post_init__(self) -> None:
        scope = str(self.recommendation_scope or "resource").strip().lower()
        if scope not in VALID_RECOMMENDATION_SCOPES:
            raise ValueError(
                f"Invalid recommendation scope {scope!r} for {self.key!r}."
            )
        object.__setattr__(self, "recommendation_scope", scope)
        priority = str(self.priority or "medium").strip().lower()
        if priority not in VALID_PRIORITIES:
            raise ValueError(
                f"Invalid recommendation priority {priority!r} for {self.key!r}."
            )
        object.__setattr__(self, "priority", priority)


@dataclass(frozen=True, slots=True)
class RecommendationRoute:
    """Finding-type -> recommendation key. ``None`` = diagnostic only."""

    recommendation_key: str | None = None


class RecommendationCatalog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = (
            path
            if path is not None
            else (Path(__file__).resolve().parent / "recommendation_rules.yaml")
        )
        if not self.path.exists():
            raise FileNotFoundError(f"Recommendation rules not found: {self.path}")
        with open(self.path, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
        if not isinstance(data, dict):
            raise ValueError("recommendation_rules.yaml must contain a mapping.")
        self.version = str((data.get("catalog") or {}).get("version", "unknown"))
        self.definitions = self._load_definitions(data.get("recommendations", {}))
        self.routes = self._load_routes(data.get("routes", {}))
        self._validate()

    @staticmethod
    def _string_tuple(value: Any) -> tuple[str, ...]:
        if not isinstance(value, list):
            return ()
        return tuple(str(item).strip() for item in value if str(item).strip())

    @staticmethod
    def _mapping(
        value: Any, *, field_name: str, recommendation_key: str
    ) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"{recommendation_key!r}.{field_name} must be a mapping.")
        return dict(value)

    @classmethod
    def _load_definitions(cls, value: Any) -> dict[str, RecommendationDefinition]:
        if not isinstance(value, dict):
            raise ValueError("'recommendations' must be a mapping.")
        result: dict[str, RecommendationDefinition] = {}
        for key, raw in value.items():
            key_string = str(key)
            if not isinstance(raw, dict):
                raise ValueError(f"Recommendation {key_string!r} must be a mapping.")
            output_constraints = cls._mapping(
                raw.get("output_constraints"),
                field_name="output_constraints",
                recommendation_key=key_string,
            )
            financial_basis = cls._mapping(
                raw.get("financial_basis"),
                field_name="financial_basis",
                recommendation_key=key_string,
            )
            result[key_string] = RecommendationDefinition(
                key=key_string,
                family=str(raw.get("family", "")).strip(),
                action=str(raw.get("action", "")).strip(),
                display_action=str(raw.get("display_action", "")).strip(),
                priority=str(raw.get("priority", "medium")).strip().lower(),
                recommendation_eligible=bool(raw.get("recommendation_eligible", True)),
                recommendation_scope=str(raw.get("recommendation_scope", "resource"))
                .strip()
                .lower(),
                required_evidence=cls._string_tuple(raw.get("required_evidence")),
                safety_evidence=cls._string_tuple(raw.get("safety_evidence")),
                optional_evidence=cls._string_tuple(raw.get("optional_evidence")),
                never_invent=cls._string_tuple(raw.get("never_invent")),
                output_constraints=output_constraints,
                financial_basis=financial_basis,
                procedure=cls._mapping(
                    raw.get("procedure"),
                    field_name="procedure",
                    recommendation_key=key_string,
                ),
                title_template=str(raw.get("title_template", "")).strip(),
            )
        return result

    @staticmethod
    def _load_routes(value: Any) -> dict[str, RecommendationRoute]:
        if not isinstance(value, dict):
            raise ValueError("'routes' must be a mapping.")
        result: dict[str, RecommendationRoute] = {}
        for finding_type, raw in value.items():
            finding_key = str(finding_type).strip()
            if not isinstance(raw, dict):
                raise ValueError(f"Route {finding_key!r} must be a mapping.")
            raw_key = raw.get("recommendation_key")
            recommendation_key = (
                None if raw_key is None else (str(raw_key).strip() or None)
            )
            result[finding_key] = RecommendationRoute(
                recommendation_key=recommendation_key
            )
        return result

    def _validate(self) -> None:

        for key, definition in self.definitions.items():

            if key != definition.key:
                raise ValueError(
                    f"Recommendation key mismatch: {key!r} != {definition.key!r}."
                )

            if not definition.family:
                raise ValueError(f"Recommendation {key!r} has no family.")

            if not definition.action:
                raise ValueError(f"Recommendation {key!r} has no action.")

            allowed = definition.financial_basis.get("allowed", [])

            if allowed is not None:

                if not isinstance(allowed, list):
                    raise ValueError(f"{key!r}.financial_basis.allowed must be a list.")

                invalid_bases = {
                    str(item).strip()
                    for item in allowed
                    if str(item).strip()
                    and str(item).strip() not in VALID_FINANCIAL_BASES
                }

                if invalid_bases:
                    raise ValueError(
                        f"{key!r} contains unsupported financial bases: {sorted(invalid_bases)}"
                    )

            preferred = definition.financial_basis.get("preferred", [])

            if preferred is not None:

                if not isinstance(preferred, list):
                    raise ValueError(
                        f"{key!r}.financial_basis.preferred must be a list."
                    )

                for item in preferred:

                    value = str(item).strip()

                    if value and value not in VALID_FINANCIAL_BASES:
                        raise ValueError(
                            f"{key!r} contains unsupported preferred financial basis {value!r}."
                        )

        for finding_type, route in self.routes.items():

            if not finding_type.strip():
                raise ValueError("Finding route cannot have an empty key.")

            # Null route is deliberate: diagnostic finding -> no recommendation.
            if route.recommendation_key is None:
                continue

            if route.recommendation_key not in self.definitions:
                raise ValueError(
                    f"{finding_type!r} references unknown recommendation "
                    f"{route.recommendation_key!r}."
                )

    def definition(self, key: str | None) -> RecommendationDefinition | None:
        if not key:
            return None
        return self.definitions.get(str(key).strip())

    def route(self, finding_type: str) -> RecommendationRoute | None:
        if not finding_type:
            return None
        return self.routes.get(str(finding_type).strip())

    def all_definitions(self) -> dict[str, RecommendationDefinition]:
        return dict(self.definitions)

    def all_routes(self) -> dict[str, RecommendationRoute]:
        return dict(self.routes)


_catalog: RecommendationCatalog | None = None


def get_catalog() -> RecommendationCatalog:
    global _catalog
    if _catalog is None:
        _catalog = RecommendationCatalog()
    return _catalog


def reload_catalog() -> RecommendationCatalog:
    """Force a fresh catalog load. Useful in development/tests after YAML edits."""
    global _catalog
    _catalog = RecommendationCatalog()
    return _catalog


def recommendation_route_for_finding(
    finding: dict[str, Any] | None,
) -> RecommendationRoute | None:
    if not isinstance(finding, dict):
        return None
    finding_type = finding.get("finding_type") or finding.get("finding_key")
    if not finding_type:
        return None
    return get_catalog().route(str(finding_type).strip())


def get_definition(recommendation_key: str) -> RecommendationDefinition | None:
    return get_catalog().definition(recommendation_key)
