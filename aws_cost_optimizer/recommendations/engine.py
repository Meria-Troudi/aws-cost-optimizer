"""
Deterministic recommendation engine.

Contract
--------
One recommendation per eligible raw (per-resource) finding, per
finding_type -- then grouped: findings that share
``(recommendation_key, service, resource_type, region, finding_type)``
collapse into one recommendation, e.g. 3 idle NAT gateways (all
``nat_gateway_idle``) produce 1 recommendation listing all 3, but one NAT
gateway that is both ``nat_gateway_idle`` and
``nat_gateway_no_route_dependency`` produces 2 -- different finding_types
never merge, even on the same resource, because they represent different
conditions with different evidence. See ``_aggregate()``/``_merge_group()``.

There is also:

- no LLM decision making -- the LLM only explains an already-created
  recommendation;
- no savings estimation and no separate policy layer.

Sources of truth, in order:

1. the finding analyzer (sets ``recommendation_eligible``);
2. the catalog route + definition (intent, family, action, default
   priority, scope, required evidence);
3. this engine, which enforces ONLY the structural requirements the
   catalog declares and deterministically materializes the result.
"""

from __future__ import annotations

import logging
from typing import Any

from aws_cost_optimizer.analysis.financial import (
    normalize_financial_impact,
)
from aws_cost_optimizer.analysis.ranking import (
    CONFIDENCE_RANK,
    SEVERITY_RANK,
)
from aws_cost_optimizer.planner.resource_catalog import get_resource_catalog

from .catalog import (
    RecommendationDefinition,
    recommendation_route_for_finding,
)
from .plan import build_plan
from .resolver import (
    resolve_persistence_scope,
    resolve_recommendation,
)
from .scoring import score

logger = logging.getLogger(__name__)

# Catalog evidence-concept resolver.
#
# The catalog's `required_evidence` entries are SEMANTIC concepts
# ("observed_usage", "resource_state", ...) while findings carry concrete
# structures (named condition statements, evidence sections, configuration).
# This table is the single, deterministic mapping between the two -- it only
# ever CHECKS PRESENCE of already-collected evidence; it never decides
# eligibility (that belongs to the analyzer) and never invents values.
#
# Probe kinds per concept:
#   sections            non-empty named subsections of finding["evidence"]
#   config_keys         keys present in finding["evidence"]["configuration"]
#   condition_substrings  substring match against condition statement names
#   summary_substrings    substring match against evidence_summary lines
#   finding_keys        top-level finding keys
#   needs_observation_period  finding["observation_period"] must be non-empty
#
# A concept not listed here falls back to exact-key lookups only (and thus
# reports itself missing in the contract warning until mapped).


def _section_mentions_concept(section: Any, requirement: str) -> bool:
    """
    True when the evidence concept (or its normalized form) actually
    appears in the section's keys or string values, at any depth.

    Used by probes that declare ``require_concept_in_section``: a
    non-empty section wrapper (e.g. a topology block that only carries
    a collection ``status``) must not be mistaken for real evidence.
    """

    normalized = requirement.replace("_", " ")

    def _walk(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                requirement in str(key).lower()
                or normalized in str(key).lower()
                or _walk(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(_walk(item) for item in value)
        if isinstance(value, str):
            text = value.lower()
            return requirement in text or normalized in text
        return False

    return _walk(section)


_EVIDENCE_CONCEPT_PROBES: dict[str, dict[str, Any]] = {
    # --- activity / usage ------------------------------------------
    "observed_usage": {
        "sections": ("metrics", "derived"),
        "condition_substrings": (
            "traffic",
            "connection",
            "request",
            "association",
            "attachment",
            "activity",
            "operations",
        ),
        "summary_substrings": ("traffic", "connection", "request"),
    },
    "observed_demand": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("demand", "traffic", "connection", "request"),
    },
    "capacity_usage": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("consumed", "capacity", "usage", "request"),
    },
    "read_traffic": {
        "sections": ("metrics",),
        "condition_substrings": ("read", "traffic", "replica"),
    },
    "storage_usage": {
        "sections": ("metrics", "derived"),
        "config_keys": ("size_gib", "allocated_storage", "volume_type"),
        "condition_substrings": ("storage", "size"),
    },
    "traffic": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("traffic",),
    },
    # --- patterns -----------------------------------------------------
    "activity_pattern": {
        "sections": ("derived",),
        "condition_substrings": ("pattern", "activity", "schedule"),
    },
    "demand_pattern": {
        "sections": ("derived",),
        "condition_substrings": ("pattern", "variation", "demand"),
    },
    "workload_pattern": {
        "sections": ("derived",),
        "condition_substrings": ("pattern", "workload", "activity"),
    },
    "workload_variability": {
        "sections": ("derived",),
        "condition_substrings": ("variation", "pattern", "peak"),
    },
    "usage_stability": {
        "sections": ("derived",),
        "condition_substrings": ("stability", "variation", "pattern"),
    },
    # --- state ----------------------------------------------------------
    "resource_state": {
        "config_keys": (
            "state",
            "status",
            "associated",
            "attached",
            "instance_state",
        ),
        "condition_substrings": ("state", "status", "associat"),
    },
    "resource_status": {
        "config_keys": ("status", "state"),
        "condition_substrings": ("status", "state"),
    },
    "autoscaling_state": {
        "config_keys": ("autoscaling_enabled", "scaling_policy", "auto_pause"),
        "condition_substrings": ("autoscaling", "scaling", "auto_pause"),
    },
    "billing_mode": {
        "sections": ("billing",),
        "config_keys": ("billing_mode",),
        "condition_substrings": ("billing_mode", "billing"),
    },
    "attachment_state": {
        "config_keys": ("attached", "attachment_count"),
        "condition_substrings": ("attachment", "associated"),
    },
    # --- capacity ---------------------------------------------------------
    "current_capacity": {
        "config_keys": (
            "iops",
            "throughput_mibps",
            "size_gib",
            "volume_type",
            "instance_class",
            "allocated_storage",
            "min_capacity",
            "max_capacity",
            "desired_capacity",
        ),
        "condition_substrings": (
            "capacity",
            "provisioned",
            "iops",
            "throughput",
            "class",
        ),
    },
    "configured_capacity": {
        "config_keys": (
            "iops",
            "throughput_mibps",
            "size_gib",
            "instance_class",
            "min_capacity",
            "max_capacity",
            "desired_capacity",
        ),
        "condition_substrings": ("capacity", "configured", "provisioned"),
    },
    "utilization": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("utilization",),
    },
    "peak_behavior": {
        "sections": ("derived",),
        "condition_substrings": ("peak", "maximum", "burst"),
    },
    "performance": {
        "sections": ("metrics",),
        "condition_substrings": (
            "cpu",
            "memory",
            "latency",
            "performance",
            "connection",
        ),
    },
    "throttling": {
        "sections": ("metrics",),
        "condition_substrings": ("throttl",),
    },
    "iops_usage": {
        "sections": ("metrics",),
        "condition_substrings": ("iops",),
    },
    "throughput_usage": {
        "sections": ("metrics",),
        "condition_substrings": ("throughput",),
    },
    # --- relationships / safety ---------------------------------------------
    "dependencies": {
        "sections": ("topology",),
        # A non-empty topology section alone does NOT prove dependency
        # evidence: disabled or contentless topology (e.g. {"status": "ok"})
        # must stay "missing evidence", not pass the gate.
        "require_concept_in_section": True,
        "condition_substrings": (
            "route",
            "subnet",
            "attachment",
            "dependency",
            "interface",
            "target_group",
            "protected",
            "associat",
        ),
    },
    "failover_context": {
        "sections": ("topology", "configuration"),
        "condition_substrings": ("failover", "multi_az", "replica"),
    },
    "workload_requirements": {
        "sections": ("topology", "configuration"),
    },
    "recovery_requirements": {
        "sections": ("topology", "configuration"),
        "condition_substrings": ("backup", "retention", "failover"),
    },
    # --- replication -----------------------------------------------------------
    "replica_usage": {
        "sections": ("topology",),
        "condition_substrings": ("replica", "reader"),
    },
    "replica_regions": {
        "config_keys": ("replica_regions", "replicas", "global_table"),
        "condition_substrings": ("replica", "region", "global"),
    },
    "regional_usage": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("region", "traffic"),
    },
    "replication_configuration": {
        "config_keys": ("replica_regions", "replicas"),
        "condition_substrings": ("replication", "replica", "global"),
    },
    "replication_lag": {
        "sections": ("metrics",),
        "condition_substrings": ("lag", "replication"),
    },
    # --- network -----------------------------------------------------------------
    "routing": {
        "sections": ("topology",),
        "condition_substrings": ("route", "routing", "subnet"),
    },
    "topology": {
        "sections": ("topology",),
    },
    "source": {
        "sections": ("topology", "metrics"),
        "condition_substrings": ("source", "ingress"),
    },
    "destination": {
        "sections": ("topology", "metrics"),
        "condition_substrings": ("destination", "egress"),
    },
    # --- endpoints ------------------------------------------------------------------
    "endpoint_configuration": {
        "config_keys": ("endpoint_type", "vpc_endpoint_id", "service_name"),
        "condition_substrings": ("endpoint",),
    },
    "endpoint_usage": {
        "sections": ("metrics",),
        "condition_substrings": ("endpoint", "traffic"),
    },
    # --- scheduling / backup --------------------------------------------------------
    "observation_window": {
        "needs_observation_period": True,
        "condition_substrings": ("period", "window", "observation"),
    },
    "recent_activity": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("activity", "connection", "request"),
    },
    "historical_activity": {
        "sections": ("billing", "derived"),
        "condition_substrings": ("historical", "activity"),
    },
    "idle_periods": {
        "sections": ("derived",),
        "condition_substrings": ("idle", "period"),
    },
    # --- storage / backup -------------------------------------------------------------
    "growth": {
        "config_keys": ("snapshot_id", "size_gib"),
        "condition_substrings": ("growth", "snapshot", "change"),
    },
    "retention": {
        "config_keys": ("backup_retention_days",),
        "condition_substrings": ("retention", "backup", "snapshot"),
    },
    "backup_usage": {
        "sections": ("billing",),
        "config_keys": ("backup_retention_days", "snapshot_id"),
        "condition_substrings": ("backup", "snapshot"),
    },
    "backup_age": {
        "condition_substrings": ("backup", "snapshot"),
    },
    "backup_frequency": {
        "condition_substrings": ("backup", "snapshot"),
    },
    # --- pricing / commitments ----------------------------------------------------------
    "pricing_eligibility": {
        "sections": ("billing",),
        "condition_substrings": ("pricing", "reserved", "commitment"),
    },
    "eligible_usage": {
        "sections": ("billing", "metrics"),
        "condition_substrings": ("eligible", "reserved", "usage"),
    },
    "existing_commitments": {
        "sections": ("billing",),
        "condition_substrings": ("commitment", "reservation", "reserved"),
    },
    "historical_usage": {
        "sections": ("billing", "derived"),
        "condition_substrings": ("historical", "usage"),
    },
    "commitment_eligibility": {
        "sections": ("billing",),
        "condition_substrings": ("commitment", "reserved", "eligib"),
    },
    "current_pricing": {
        "sections": ("billing",),
        "condition_substrings": ("pricing", "cost"),
    },
    # --- v3.0 catalog concepts -------------------------------------------
    "resource_identity": {
        "config_keys": (
            "nat_gateway_id",
            "allocation_id",
            "volume_id",
            "load_balancer_arn",
            "db_instance_identifier",
            "cluster_identifier",
            "instance_id",
            "table_name",
            "resource_id",
        ),
        "condition_substrings": ("id", "identifier", "arn", "name"),
    },
    "active_connections": {
        "sections": ("metrics",),
        "condition_substrings": ("connection",),
    },
    "route_dependency": {
        "sections": ("topology",),
        "condition_substrings": ("route", "subnet"),
    },
    "access_pattern": {
        "sections": ("metrics", "derived"),
        "require_concept_in_section": True,
        "condition_substrings": ("access", "pattern", "request"),
    },
    "association_state": {
        "config_keys": ("associated", "association_id", "state"),
        "condition_substrings": ("associat", "state"),
    },
    "current_configuration": {
        "sections": ("configuration",),
    },
    "current_network_path": {
        "sections": ("topology",),
        "condition_substrings": ("route", "path", "traffic"),
    },
    "current_storage_class": {
        "config_keys": ("storage_class", "volume_type", "storage_type"),
        "condition_substrings": ("storage", "class", "type"),
    },
    "current_volume_type": {
        "config_keys": ("volume_type",),
        "condition_substrings": ("volume", "type"),
    },
    "interruption_tolerance": {
        "condition_substrings": ("interrupt", "spot", "tolerance"),
    },
    "cpu_allocation": {
        "config_keys": ("cpu", "cpu_request", "pod_cpu"),
        "condition_substrings": ("cpu",),
    },
    "cpu_utilization": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("cpu",),
    },
    "memory_allocation": {
        "config_keys": ("memory", "memory_reserved", "pod_memory"),
        "condition_substrings": ("memory",),
    },
    "memory_utilization": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("memory",),
    },
    "node_capacity": {
        "config_keys": ("node_count", "desired_capacity", "instance_type"),
        "condition_substrings": ("node", "capacity"),
    },
    "object_or_data_age": {
        "condition_substrings": ("age", "last", "created"),
    },
    "observed_activity": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("activity", "request", "connection", "traffic"),
    },
    "observed_state": {
        "config_keys": ("state", "status"),
        "condition_substrings": ("state", "status"),
    },
    "peak_cpu_behavior": {
        "sections": ("derived",),
        "condition_substrings": ("cpu", "peak"),
    },
    "peak_memory_behavior": {
        "sections": ("derived",),
        "condition_substrings": ("memory", "peak"),
    },
    "resource_inventory": {
        "sections": ("configuration", "topology"),
        "condition_substrings": ("count", "inventory"),
    },
    "resource_relationships": {
        "sections": ("topology",),
        "condition_substrings": ("relationship", "association", "attachment"),
    },
    "replication_configuration": {
        "config_keys": ("replication_enabled", "replication_rule_count"),
        "condition_substrings": ("replication",),
    },
    "retention_behavior": {
        "config_keys": (
            "backup_retention_days",
            "lifecycle_enabled",
            "lifecycle_rule_count",
        ),
        "condition_substrings": ("retention", "lifecycle"),
    },
    "scaling_behavior": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("scaling", "autoscaling"),
    },
    "sustained_underutilization": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("utilization", "underutiliz"),
    },
    "target_count": {
        "condition_substrings": ("target",),
    },
    "volume_configuration": {
        "config_keys": ("volume_type", "iops", "throughput_mibps", "size_gib"),
        "condition_substrings": ("volume", "iops", "throughput"),
    },
    "workload_behavior": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("workload", "traffic", "pattern"),
    },
    "workload_demand": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("demand", "traffic", "cpu"),
    },
    "workload_type": {
        "config_keys": ("engine", "platform", "tenancy", "instance_type"),
        "condition_substrings": ("workload", "type", "engine"),
    },
    "finding_evidence": {
        "sections": ("metrics", "derived", "configuration"),
    },
    "usage_pattern": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("pattern", "usage", "activity"),
    },
    # --- architecture / generic --------------------------------------------
    "configuration": {
        "sections": ("configuration",),
    },
    "observed_behavior": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("traffic", "connection", "request", "behavior"),
    },
    "current_architecture": {
        "sections": ("topology", "configuration"),
    },
    # --- WAF / Aurora / VPC-endpoint concepts ------------------------------
    "attachments": {
        "sections": ("topology",),
        "condition_substrings": ("attachment", "associat"),
    },
    "body_inspection_configuration": {
        "config_keys": ("body_inspection_enabled", "inspect_body", "oversize_handling"),
        "condition_substrings": ("body", "inspection"),
    },
    "bot_control_configuration": {
        "config_keys": (
            "bot_control_enabled",
            "managed_rule_group",
            "aws_managed_bot_control",
        ),
        "condition_substrings": ("bot", "control"),
    },
    "captcha_activity": {
        "sections": ("derived", "metrics"),
        "condition_substrings": ("captcha",),
    },
    "challenge_activity": {
        "sections": ("derived", "metrics"),
        "condition_substrings": ("challenge",),
    },
    "endpoint_state": {
        "config_keys": ("state", "status", "vpc_endpoint_id"),
        "condition_substrings": ("state", "status", "endpoint"),
    },
    "endpoint_type": {
        "config_keys": ("endpoint_type",),
        "condition_substrings": ("endpoint", "type"),
    },
    "interface_network_interfaces": {
        "config_keys": ("network_interface_ids", "eni_ids", "subnet_ids"),
        "condition_substrings": ("network interface", "eni", "interface"),
    },
    "managed_rule_groups": {
        "config_keys": ("managed_rule_groups", "rule_groups", "managed_rule_group"),
        "condition_substrings": ("managed", "rule group", "managed_rule"),
    },
    "observation_period": {
        "needs_observation_period": True,
        "condition_substrings": ("period", "observation", "window"),
    },
    "observed_traffic": {
        "sections": ("metrics", "derived"),
        "condition_substrings": ("traffic", "byte", "request"),
    },
    "request_activity": {
        "sections": ("derived", "metrics"),
        "condition_substrings": ("request", "activity"),
    },
    "request_volume": {
        "sections": ("derived", "metrics"),
        "config_keys": ("request_volume",),
        "condition_substrings": ("request", "volume"),
    },
    "route_configuration": {
        "sections": ("topology",),
        "condition_substrings": ("route", "gateway route"),
    },
    "route_or_interface_configuration": {
        "sections": ("topology",),
        "condition_substrings": ("route", "interface", "subnet"),
    },
    "rule_configuration": {
        "config_keys": ("rule_count", "rules", "capacity"),
        "condition_substrings": ("rule", "capacity"),
    },
    "rule_count": {
        "config_keys": ("rule_count",),
        "condition_substrings": ("rule", "count"),
    },
    "rule_inventory": {
        "sections": ("configuration",),
        "config_keys": ("rule_groups", "rules"),
        "condition_substrings": ("rule", "inventory"),
    },
    "subnet_configuration": {
        "config_keys": ("subnet_ids",),
        "condition_substrings": ("subnet",),
    },
    "subnet_scope": {
        "config_keys": ("subnet_scope",),
        "condition_substrings": ("subnet", "scope"),
    },
    "wcu_usage": {
        "config_keys": ("capacity_wcu", "wcu"),
        "condition_substrings": ("wcu", "capacity"),
    },
}


class RecommendationEngine:

    SEVERITY_RANK = SEVERITY_RANK

    CONFIDENCE_RANK = CONFIDENCE_RANK

    def generate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        if not isinstance(
            findings,
            list,
        ):
            return []

        per_resource: list[dict[str, Any]] = []

        for finding in findings:

            try:
                recommendation = self._build_one(finding)

            except Exception:

                # A single malformed/incomplete finding must never
                # abort recommendation generation for the rest of
                # the scan.
                finding_type = (
                    finding.get("finding_type")
                    if isinstance(
                        finding,
                        dict,
                    )
                    else None
                )

                logger.warning(
                    "Skipping finding %r during " "recommendation generation",
                    finding_type,
                    exc_info=True,
                )

                continue

            if recommendation is not None:
                per_resource.append(recommendation)

        return sorted(
            self._aggregate(per_resource),
            key=self._sort_key,
        )

    # AGGREGATION

    def _aggregate(
        self,
        recommendations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Collapse per-resource recommendations into one per group.

        Group key: (recommendation_key, service, resource_type, region,
        finding_type). `finding_type` IS part of the key -- different
        finding_types never merge, even when they route to the same
        recommendation_key on the same resource, because they represent
        different conditions with different evidence and the recommendation
        must respect that rather than silently presenting one finding's
        specific reason as if it covered both. Whatever the engine receives
        is grouped strictly by finding_type. This is why the ELB analyzer
        now canonicalizes: it emits at most ONE canonical finding
        (elb_idle_with_cost / elb_idle) per idle load balancer, so an ELB
        never reaches the engine as multiple different finding_types -- the
        "one resource → one removal recommendation" behaviour is enforced at
        the analyzer, not here. Findings that share every part of the key --
        most commonly the same finding_type on several different resources,
        e.g. 3 idle NAT gateways -- collapse into ONE recommendation whose
        affected_resources / source_finding_ids list every member.

        There's no separate catalog-level opt-in for this: grouping by
        finding_type inherently produces the right granularity for both
        cases without a flag, because resource-scoped findings only ever
        share a finding_type with something else when they're genuinely
        the same kind of problem, while account-scoped commitment
        findings (Savings Plans, Reserved Instances) each map to exactly
        one finding_type per route, so they keep aggregating across every
        matching resource in the account exactly as before.

        Persisted scope/variant disambiguation happens in `_merge_group()`
        -- see its docstring for how two different finding_type groups
        that land on the same resource avoid colliding on the DB's
        (scan_run_id, recommendation_key, recommendation_variant,
        resource_type, scope) unique constraint.
        """

        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}

        for recommendation in recommendations:

            finding_type = str((recommendation.get("source_finding_types") or [""])[0])

            key_parts = [
                str(recommendation.get("recommendation_key") or ""),
                str(recommendation.get("service") or ""),
                str(recommendation.get("resource_type") or ""),
                str(recommendation.get("region") or "unknown"),
                finding_type,
            ]

            groups.setdefault(tuple(key_parts), []).append(recommendation)

        result: list[dict[str, Any]] = []

        for members in groups.values():

            merged = self._merge_group(members)

            if merged is not None:
                result.append(merged)

        return result

    def _merge_group(
        self,
        members: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """
        Merge one _aggregate() group into a single recommendation.

        Every member already shares (recommendation_key, service,
        resource_type, region, finding_type) -- see _aggregate(). What
        can still differ between members is their individual `scope`
        (resource_type-scoped findings each start with their own
        `resource:<id>`; account-scoped findings already all share one
        `account:<id>`).

        Persisted `scope` is derived from whether the members already
        agree: if they do (a single-member group, or an account-scoped
        group where every member's scope was already identical), keep it
        as-is; otherwise (multiple distinct resources sharing one
        finding_type, e.g. 3 idle NAT gateways) fall back to a
        region-level group identity, since no single member's resource id
        can represent the whole group.

        `recommendation_variant` is set to the group's finding_type. This
        is what stops two DIFFERENT finding_type groups on the very same
        resource from colliding: both groups would otherwise persist under
        the identical (recommendation_key, resource_type, scope) tuple,
        which is exactly the collision this project hit once before (an
        arbitrary member survived, presenting a HIGH finding as a LOW
        recommendation) -- `recommendation_variant` already exists
        end-to-end for precisely this (DB column, upsert-lookup filter,
        presenter output), it was just always None. (In practice the ELB
        analyzer now emits at most one canonical finding per load balancer,
        so it no longer feeds the engine multiple differing finding_types
        for the same resource; the variant collision protection remains for
        any other analyzer that does.)
        """

        if not members:
            return None

        # The group's representative is its highest-severity member, so
        # the surviving title/reason describe the strongest evidence for
        # the remedy rather than whichever member happened to sort first.
        # Every member already shares recommendation_key, resource_type,
        # region and scope, so the other fields read off it are identical.
        first = max(
            members,
            key=lambda r: self.SEVERITY_RANK.get(
                str(r.get("priority") or "low").lower(),
                0,
            ),
        )

        members.sort(
            key=lambda r: ",".join(str(x) for x in (r.get("affected_resources") or []))
        )

        affected_resources: list[str] = []
        source_finding_ids: list[int] = []
        source_finding_types: list[str] = []
        evidence: list[dict[str, Any]] = []
        limitations: list[str] = []
        seen_limitations: set[str] = set()

        for member in members:

            for item in member.get("affected_resources") or []:
                text = str(item)
                if text and text not in affected_resources:
                    affected_resources.append(text)

            for item in member.get("source_finding_ids") or []:
                if item is not None and int(item) not in source_finding_ids:
                    source_finding_ids.append(int(item))

            for item in member.get("source_finding_types") or []:
                text = str(item)
                if text and text not in source_finding_types:
                    source_finding_types.append(text)

            for item in member.get("evidence") or []:
                if isinstance(item, dict):
                    evidence.append(item)

            for item in member.get("limitations") or []:
                text = str(item).strip()
                if text and text not in seen_limitations:
                    seen_limitations.add(text)
                    limitations.append(text)

        region = next(
            (m.get("region") for m in members if m.get("region")),
            None,
        )

        distinct_scopes = {m.get("scope") for m in members}

        scope = (
            first.get("scope")
            if len(distinct_scopes) == 1
            else (f"region:{region}" if region else first.get("scope"))
        )

        return {
            "service": first.get("service"),
            "recommendation_key": first.get("recommendation_key"),
            "recommendation_variant": (
                source_finding_types[0] if source_finding_types else None
            ),
            "recommendation_scope": first.get("recommendation_scope"),
            "resource_type": first.get("resource_type"),
            "scope": scope,
            "category": first.get("category"),
            "title": first.get("title"),
            # Highest-severity member wins, the same way confidence does.
            # Taking first.get("priority") let an arbitrary low-severity
            # member of the group set the priority of a remedy that a
            # high-severity finding also justifies.
            "priority": max(
                (str(m.get("priority") or "low").lower() for m in members),
                key=lambda value: self.SEVERITY_RANK.get(value, 0),
            ),
            "confidence": max(
                (str(m.get("confidence") or "low").lower() for m in members),
                key=lambda value: self.CONFIDENCE_RANK.get(value, 0),
            ),
            "reason": first.get("reason"),
            "action": first.get("action"),
            "plan": first.get("plan"),
            "region": region,
            "affected_resources": affected_resources,
            "affected_resource_count": len(affected_resources),
            "source_finding_ids": source_finding_ids,
            "source_finding_types": source_finding_types,
            "source_finding_count": len(source_finding_ids),
            "finding_id": (source_finding_ids[0] if source_finding_ids else None),
            "limitations": limitations,
            "evidence": evidence,
            "financial_impact": self._aggregate_financial_impact(members),
            "status": "requires_validation",
            "supporting_finding_count": max(len(members) - 1, 0),
        }

    @staticmethod
    def _aggregate_financial_impact(
        members: list[dict[str, Any]],
    ) -> dict[str, Any]:

        if not members:
            return {}

        # Shared / collection-plan billing must never be multiplied by
        # the number of resources in the group: when every member carries
        # the same non-attributed bucket, report the bucket once.
        # Resource-attributed (claimable) costs are summed.
        # Shared / collection-plan billing must never be multiplied by
        # the number of resources in the group: when every member carries
        # the same non-attributed bucket, report the bucket once.
        # Resource-attributed (claimable) costs are summed, including
        # any genuine estimated savings from full-elimination findings.
        claimable_observed = 0.0
        claimable_estimated = 0.0
        has_claimable = False
        has_estimated_savings = False
        shared: float | None = None
        shared_basis: str | None = None

        _SHARED_BASES = {
            "cost_not_resource_attributed",
            "billing_usage_type_mismatch",
        }

        for member in members:

            impact = member.get("financial_impact") or {}
            observed = impact.get("observed_monthly_cost")
            basis = impact.get("savings_basis") or ""

            # A shared/collection-plan basis means calculate_savings()
            # already, correctly, left observed_monthly_cost as None for
            # this member (never report an unattributed bucket as this
            # resource's own cost) -- so the basis must be captured here,
            # before the numeric check below, or every member in a group
            # that shares this basis gets skipped and the group silently
            # falls back to the far less informative "unknown" (this was
            # a real bug: the numeric check ran unconditionally first,
            # making the code that captured `shared` unreachable whenever
            # observed was None, which -- per calculate_savings() -- it
            # always is for this basis).
            if basis in _SHARED_BASES and shared_basis is None:
                shared_basis = basis

            if not isinstance(observed, (int, float)):
                continue

            value = float(observed)

            if basis in _SHARED_BASES:
                if shared is None:
                    shared = value
                continue

            has_claimable = True
            claimable_observed += value

            savings = impact.get("estimated_monthly_savings")

            if isinstance(savings, (int, float)) and not isinstance(
                savings,
                bool,
            ):
                has_estimated_savings = True
                claimable_estimated += float(savings)

        if has_claimable:
            return {
                "observed_monthly_cost": round(claimable_observed, 2),
                "estimated_monthly_savings": (
                    round(claimable_estimated, 2) if has_estimated_savings else None
                ),
                "savings_confidence": ("high" if has_estimated_savings else None),
                "savings_basis": (
                    "resource_attributed_cost"
                    if not has_estimated_savings
                    else "full_resource_elimination"
                ),
                "currency": "USD",
            }

        return {
            "observed_monthly_cost": (round(shared, 2) if shared is not None else None),
            "estimated_monthly_savings": None,
            "savings_confidence": None,
            "savings_basis": shared_basis or "unknown",
            "currency": "USD",
        }

    # BUILD

    def _build_one(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any] | None:

        if not isinstance(
            finding,
            dict,
        ):
            return None

        if finding.get("recommendation_eligible") is not True:
            return None

        route = recommendation_route_for_finding(finding)

        if route is None:
            return None

        definition = resolve_recommendation(finding)

        if definition is None:
            return None

        # Catalog-level eligibility: a definition can be disabled in
        # the YAML catalog independently of any finding's flag.
        if definition.recommendation_eligible is not True:
            return None

        # Required evidence is the only structural validation here --
        # there is no separate policy layer. The catalog declares what
        # evidence must exist, and this is now a real gate: a finding
        # missing catalog-required evidence does not become a
        # recommendation. Verified safe to enforce (not just warn) by
        # running every currently-eligible finding type produced by a
        # real scan through this check first -- all passed with zero
        # missing concepts; the require_concept_in_section probe flag
        # (see _section_mentions_concept) is what makes a contentless
        # wrapper section (e.g. {"status": "disabled"}) correctly fail
        # rather than being mistaken for real evidence.
        missing = self._missing_required_evidence(
            finding,
            definition,
        )

        if missing:
            logger.warning(
                "Finding %s (%s) is missing catalog-required evidence "
                "concepts: %s -- no recommendation generated.",
                finding.get("resource_id", "unknown"),
                finding.get("finding_type", "unknown"),
                ", ".join(missing),
            )
            return None

        finding_id = self._finding_id(finding)

        if finding_id is None:
            raise RuntimeError("Eligible finding has no persisted " "database ID.")

        scope = resolve_persistence_scope(
            recommendation_scope=(definition.recommendation_scope),
            finding=finding,
        )

        priority, confidence = score(
            finding,
            definition.priority,
        )

        resource_id = finding.get("resource_id")

        resource_type = (
            str(finding.get("resource_type") or "unknown").strip() or "unknown"
        )

        finding_type = str(
            finding.get("finding_type") or finding.get("finding_key") or "finding"
        )

        # The title must name the resource's actual AWS service (e.g.
        # "Amazon EBS"), not the billing service the cost happened to
        # be reported under (e.g. "EC2 - Other", which NAT gateways,
        # Transit Gateways, and EBS volumes all share). resource_type
        # is the correct, per-finding-unique join key for that lookup
        # -- billing classification itself is untouched, this only
        # affects the display label.
        resource_service = (
            get_resource_catalog().group_for(resource_type).get("service")
        )

        title = self._title_for(
            definition,
            resource_service or finding.get("service"),
        )

        action = str(definition.display_action or "").strip() or (
            str(definition.action or "review")
            .replace(
                "_",
                " ",
            )
            .title()
        )

        reason = str(finding.get("reason") or "").strip()

        if not reason:
            reason = (
                "The recommendation is supported by " "the collected finding evidence."
            )

        impact = finding.get("impact")

        if not isinstance(
            impact,
            dict,
        ):
            impact = {}

        financial_impact = normalize_financial_impact(impact)

        limitations = [
            str(item).strip()
            for item in (finding.get("limitations") or [])
            if str(item).strip()
        ]

        evidence = [
            {
                "finding_id": finding_id,
                "finding_type": finding_type,
                "resource_id": resource_id,
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "reason": finding.get("reason"),
                "evidence_summary": finding.get(
                    "evidence_summary",
                    [],
                ),
                "conditions": finding.get(
                    "conditions",
                    [],
                ),
                "limitations": finding.get(
                    "limitations",
                    [],
                ),
            }
        ]

        service = str(finding.get("service") or "Unknown service")

        return {
            "service": service,
            "recommendation_key": route.recommendation_key,
            "recommendation_variant": None,
            "recommendation_scope": definition.recommendation_scope,
            "resource_type": resource_type,
            "scope": scope,
            "category": definition.family,
            "title": title,
            "priority": priority,
            "confidence": confidence,
            "reason": reason,
            "action": action,
            "plan": build_plan(definition),
            "region": finding.get("region"),
            "affected_resources": [resource_id] if resource_id else [],
            "source_finding_ids": [finding_id],
            "source_finding_types": [finding_type],
            "source_finding_count": 1,
            "finding_id": finding_id,
            "limitations": limitations,
            "evidence": evidence,
            "financial_impact": financial_impact,
            "status": "requires_validation",
            "supporting_finding_count": 0,
        }

    # EVIDENCE VALIDATION

    @classmethod
    def _missing_required_evidence(
        cls,
        finding: dict[str, Any],
        definition: RecommendationDefinition,
    ) -> list[str]:

        return [
            requirement
            for requirement in definition.required_evidence
            if not cls._has_evidence(finding, requirement)
        ]

    @staticmethod
    def _has_evidence(
        finding: dict[str, Any],
        requirement: str,
    ) -> bool:
        """
        Structural presence check for one catalog evidence concept.

        The analyzer decides whether its finding is valid; this only
        verifies that the evidence the catalog declares actually exists
        on the finding. A requirement is satisfied when a meaningful
        value is found in any of:

            finding[requirement]
            finding["evidence"][requirement]      (+ nested dicts)
            finding["conditions"][i]["name"]      contains requirement
            finding["evidence_summary"][i]        mentions requirement

        Conditions and evidence summaries are lists of records in this
        project's finding shape, so name/substring matching is the
        deterministic equivalent of the analyzer having stated the
        fact. Empty containers are absence of evidence.
        """

        requirement = str(requirement or "").strip().lower()

        if not requirement:
            return True

        def _meaningful(value: Any) -> bool:
            if value is None:
                return False
            if isinstance(value, str):
                return bool(value.strip())
            if isinstance(value, (list, tuple, dict)):
                return len(value) > 0
            return True

        # 1. Top-level key.
        if _meaningful(finding.get(requirement)):
            return True

        # 1b. Every finding always carries its own resource_id -- that
        # alone already satisfies "resource_identity" without requiring
        # a per-service configuration key name to also be whitelisted.
        if requirement == "resource_identity" and _meaningful(
            finding.get("resource_id")
        ):
            return True

        # 2. Evidence block, including nested sections.
        evidence = finding.get("evidence")

        if isinstance(evidence, dict):

            if _meaningful(evidence.get(requirement)):
                return True

            for section in evidence.values():
                if isinstance(section, dict) and _meaningful(section.get(requirement)):
                    return True

        # 3. Condition statements (name or nested value key).
        conditions = finding.get("conditions")

        if isinstance(conditions, list):
            for condition in conditions:
                if not isinstance(condition, dict):
                    continue
                name = str(condition.get("name") or "").lower()
                if requirement in name:
                    return True
                value = condition.get("value")
                if isinstance(value, dict) and _meaningful(value.get(requirement)):
                    return True

        # 4. Summarized evidence text (exact + summary-substring probes).
        summary = finding.get("evidence_summary")

        if isinstance(summary, list):
            normalized = requirement.replace("_", " ")
            for item in summary:
                text = str(item or "").lower()
                if requirement in text or normalized in text:
                    return True

        # 5. Concept probes: where this semantic concept genuinely lives
        # on findings of this shape (see _EVIDENCE_CONCEPT_PROBES).
        probes = _EVIDENCE_CONCEPT_PROBES.get(requirement)

        if not probes:
            return False

        require_concept_in_section = probes.get(
            "require_concept_in_section",
            False,
        )

        for section_name in probes.get("sections", ()):
            section = evidence.get(section_name) if isinstance(evidence, dict) else None
            if not _meaningful(section):
                continue
            if require_concept_in_section and not _section_mentions_concept(
                section,
                requirement,
            ):
                continue
            return True

        configuration = (
            evidence.get("configuration") if isinstance(evidence, dict) else None
        )

        if isinstance(configuration, dict):
            for key in probes.get("config_keys", ()):
                value = configuration.get(key)
                if value is not None and (not isinstance(value, str) or value.strip()):
                    return True

        condition_substrings = probes.get("condition_substrings", ())

        if condition_substrings and isinstance(conditions, list):
            for condition in conditions:
                if not isinstance(condition, dict):
                    continue
                name = str(condition.get("name") or "").lower()
                if any(sub in name for sub in condition_substrings):
                    return True

        if condition_substrings and isinstance(summary, list):
            for item in summary:
                text = str(item or "").lower()
                if any(sub in text for sub in condition_substrings):
                    return True

        for substr in probes.get("summary_substrings", ()):
            if isinstance(summary, list):
                for item in summary:
                    if substr in str(item or "").lower():
                        return True
            elif isinstance(conditions, list):
                # Fall back to reason text when no summaries exist.
                reason = str(finding.get("reason") or "").lower()
                if substr in reason:
                    return True

        if probes.get("needs_observation_period"):
            period = finding.get("observation_period")

            if _meaningful(period):
                return True

            resource = evidence.get("resource") if isinstance(evidence, dict) else None

            if isinstance(resource, dict) and _meaningful(
                resource.get("observation_period")
            ):
                return True

        return False

    # HELPERS

    @staticmethod
    def _title_for(
        definition: RecommendationDefinition,
        service: Any,
    ) -> str:
        """
        Professional, action-oriented title.

        Uses the catalog's title_template when present (the preferred
        plain-language form, e.g. "Remove Idle NAT Gateway — Amazon
        VPC"), with {action}/{service}-style placeholders filled.
        Falls back to a humanized version of the action.
        """

        template = str(getattr(definition, "title_template", "") or "").strip()

        service_label = (
            str(service or "AWS service")
            .replace("Amazon ", "")
            .replace("AWS ", "")
            .strip()
            or "AWS service"
        )

        if template:
            action_label = (
                str(getattr(definition, "display_action", "") or "").strip()
                or str(definition.action or "Review").replace("_", " ").title()
            )

            return template.replace(
                "{action}",
                action_label,
            ).replace(
                "{service}",
                service_label,
            )

        action = str(definition.action or "review").replace("_", " ").strip().title()

        return f"{action} — {service_label}"

    @staticmethod
    def _finding_id(
        finding: dict[str, Any],
    ) -> int | None:

        value = finding.get("database_id")

        try:
            number = int(value)

        except (
            TypeError,
            ValueError,
        ):
            return None

        return number if number > 0 else None

    @classmethod
    def _sort_key(
        cls,
        recommendation: dict[str, Any],
    ) -> tuple[int, int, str, str]:

        priority = str(
            recommendation.get(
                "priority",
                "low",
            )
        ).lower()

        confidence = str(
            recommendation.get(
                "confidence",
                "low",
            )
        ).lower()

        return (
            -cls.SEVERITY_RANK.get(
                priority,
                0,
            ),
            -cls.CONFIDENCE_RANK.get(
                confidence,
                0,
            ),
            str(
                recommendation.get(
                    "title",
                    "",
                )
            ),
            str(
                recommendation.get(
                    "scope",
                    "",
                )
            ),
        )
