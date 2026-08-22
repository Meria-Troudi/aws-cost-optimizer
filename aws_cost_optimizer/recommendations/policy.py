"""
Recommendation safety gate.

Every catalog route declares a `required_evidence` list -- the evidence
a recommendation of that kind must be standing on. Until now nothing
checked it, so the catalog documented a safety contract that no code
upheld: a route declaring `dependencies` as mandatory would happily
emit a "remove this resource" recommendation for a finding carrying no
dependency evidence at all.

This module closes that gap.

Why concepts need resolving
---------------------------
`required_evidence` entries are abstract concepts -- "traffic",
"dependencies", "peak_behavior" -- while a finding's evidence has a
fixed concrete shape:

    evidence.{billing, configuration, data_quality, derived,
              metrics, resource, topology}
    conditions[].name
    metadata, observation_period

So "does the finding contain `traffic`?" cannot be a dict lookup. Each
concept is mapped below to the places that concept genuinely lives,
and is satisfied when any of them holds a non-empty value.

Two deliberate choices
----------------------
1. Satisfaction requires a NON-EMPTY value, not merely a present key.
   An empty metrics dict is absence of evidence, and the whole point of
   this gate is to stop recommendations resting on absence.

2. A concept with no entry in _CONCEPT_PROBES is REJECTED, not waved
   through. Adding a new concept to the catalog is therefore a visible
   action: it fails closed until someone states where that evidence
   lives. Failing open would recreate the exact silent-contract problem
   this module exists to fix.
"""

from __future__ import annotations

from typing import Any, Iterable

from .catalog import RecommendationDefinition

# Concept -> probes that can satisfy it.
#
# A probe is either:
#   "a.b.c"            dotted path into the finding dict
#   "condition:<sub>"  a condition statement whose name contains <sub>
#
# Paths are grounded in the evidence shapes analyzers actually emit;
# several concepts are legitimately satisfiable from more than one
# place because different resource types express them differently
# (NAT records traffic under derived.traffic, ELB under metrics).
_CONCEPT_PROBES: dict[str, tuple[str, ...]] = {
    # --- activity / usage -------------------------------------------
    "observed_usage": (
        "evidence.metrics",
        "evidence.derived.activity",
        "condition:count",
    ),
    "utilization": (
        "evidence.metrics",
        "evidence.derived.utilization",
        "condition:utilization",
    ),
    "observed_demand": (
        "evidence.metrics",
        "evidence.derived.activity",
    ),
    "capacity_usage": (
        "evidence.metrics",
        "evidence.derived.activity",
    ),
    "observed_behavior": (
        "evidence.metrics",
        "evidence.derived",
    ),
    "activity_pattern": (
        "evidence.metrics",
        "evidence.derived.activity",
    ),
    "workload_pattern": (
        "evidence.metrics",
        "evidence.derived.activity",
    ),
    "demand_pattern": (
        "evidence.metrics",
        "evidence.derived.activity",
        "evidence.derived.variation",
    ),
    "workload_variability": (
        "evidence.metrics",
        "evidence.derived.variation",
    ),
    "usage_stability": (
        "evidence.metrics",
        "evidence.derived.variation",
    ),
    "peak_behavior": (
        "evidence.metrics",
        "evidence.derived.variation",
        "condition:maximum",
        "condition:peak",
    ),
    # --- traffic / network ------------------------------------------
    "traffic": (
        "evidence.derived.traffic",
        "evidence.derived.activity",
        "evidence.metrics",
        "condition:traffic",
        "condition:bytes",
    ),
    "read_traffic": (
        "evidence.metrics",
        "condition:read",
    ),
    "routing": (
        "evidence.topology",
        "condition:route",
    ),
    "source": (
        "evidence.topology",
        "evidence.resource",
    ),
    "destination": (
        "evidence.topology",
        "evidence.derived.relationships",
    ),
    "topology": ("evidence.topology",),
    "dependencies": (
        "evidence.topology",
        "evidence.derived.relationships",
        "condition:dependencies",
        "condition:attachments",
        "condition:protected_resource_count",
    ),
    "current_architecture": (
        "evidence.topology",
        "evidence.configuration",
    ),
    # --- state / configuration --------------------------------------
    "resource_state": (
        "evidence.configuration.state",
        "evidence.derived.status",
        "condition:state",
        "condition:status",
        "condition:associated",
    ),
    "resource_status": (
        "evidence.configuration.state",
        "evidence.derived.status",
        "condition:state",
        "condition:status",
    ),
    "configuration": ("evidence.configuration",),
    "current_capacity": (
        "evidence.configuration",
        "condition:capacity",
        "condition:instance_class",
        "condition:target_count",
    ),
    "configured_capacity": (
        "evidence.configuration",
        "condition:capacity",
    ),
    "autoscaling_state": (
        "evidence.configuration.autoscaling",
        "evidence.derived.relationships",
        "condition:autoscaling",
        "condition:reader_count",
    ),
    "performance": (
        "evidence.metrics",
        "evidence.derived.performance",
    ),
    "performance_signals": (
        "evidence.metrics",
        "evidence.derived.performance",
        "evidence.derived.errors",
    ),
    # --- replicas / replication -------------------------------------
    "replica_usage": (
        "evidence.metrics",
        "condition:reader",
        "condition:replica",
    ),
    "replica_regions": (
        "evidence.configuration",
        "condition:global",
        "condition:region",
    ),
    "regional_usage": (
        "evidence.metrics",
        "evidence.configuration",
    ),
    "replication_configuration": (
        "evidence.configuration",
        "condition:global",
        "condition:replica",
    ),
    "failover_context": (
        "evidence.configuration",
        "evidence.topology",
    ),
    # --- storage ----------------------------------------------------
    "storage_usage": (
        "evidence.configuration",
        "evidence.metrics",
        "condition:size",
        "condition:storage",
    ),
    "growth": (
        "evidence.metrics",
        "evidence.configuration",
    ),
    # --- backup / retention -----------------------------------------
    "retention": (
        "evidence.configuration",
        "condition:retention",
        "condition:backup",
    ),
    "backup_usage": (
        "evidence.configuration",
        "condition:backup",
    ),
    "recovery_requirements": (
        "evidence.configuration",
        "condition:backup",
        "condition:retention",
    ),
    # --- billing / commitment ---------------------------------------
    "billing_mode": (
        "evidence.configuration.capacity",
        "evidence.billing",
        "condition:billing_mode",
    ),
    "eligible_usage": (
        "evidence.billing",
        "evidence.metrics",
    ),
    "existing_commitments": ("evidence.billing",),
    # --- observation window -----------------------------------------
    "observation_window": (
        "observation_period",
        "evidence.data_quality",
    ),
}


def _dig(source: Any, path: str) -> Any:
    """Resolve a dotted path, returning None if any hop is missing."""

    current = source

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

        if current is None:
            return None

    return current


def _is_present(value: Any) -> bool:
    """Non-empty evidence. Zero counts as present; empty containers do not."""

    if value is None:
        return False

    if isinstance(value, (dict, list, tuple, set, str)):
        return len(value) > 0

    return True


def _condition_names(finding: dict[str, Any]) -> list[str]:
    names: list[str] = []

    for condition in finding.get("conditions") or []:
        if isinstance(condition, dict):
            name = condition.get("name")

            if name:
                names.append(str(name).lower())

    return names


def _probe_satisfied(
    finding: dict[str, Any],
    probe: str,
    condition_names: Iterable[str],
) -> bool:

    if probe.startswith("condition:"):
        needle = probe.split(":", 1)[1].lower()
        return any(needle in name for name in condition_names)

    return _is_present(_dig(finding, probe))


def missing_evidence(
    finding: dict[str, Any],
    required: Iterable[str],
) -> list[str]:
    """Required-evidence concepts the finding does not satisfy.

    Returned entries are human-readable reasons, not bare concept
    names, so the caller can log why a recommendation was withheld.
    """

    condition_names = _condition_names(finding)
    reasons: list[str] = []

    for concept in required or []:
        key = str(concept).strip()

        if not key:
            continue

        probes = _CONCEPT_PROBES.get(key)

        if probes is None:
            reasons.append(
                f"required evidence {key!r} has no resolver defined in "
                "policy._CONCEPT_PROBES (add one stating where this "
                "evidence lives)"
            )
            continue

        if not any(
            _probe_satisfied(finding, probe, condition_names) for probe in probes
        ):
            reasons.append(
                f"required evidence {key!r} is absent (looked in: "
                f"{', '.join(probes)})"
            )

    return reasons


def validate(
    finding: dict[str, Any],
    definition: RecommendationDefinition,
) -> tuple[bool, list[str]]:
    """Decide whether a recommendation may be built from this finding."""

    errors: list[str] = []

    if not isinstance(finding, dict):
        return False, ["Finding is not a mapping."]

    if finding.get("recommendation_eligible") is not True:
        errors.append("Finding is not recommendation eligible.")

    if definition is None:
        errors.append("No recommendation definition resolved.")

        return (not errors, errors)

    if definition.recommendation_eligible is not True:
        errors.append("Recommendation definition is disabled.")

    errors.extend(
        missing_evidence(
            finding,
            getattr(definition, "required_evidence", ()) or (),
        )
    )

    return (not errors, errors)
