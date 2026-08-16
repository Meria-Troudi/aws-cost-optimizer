"""
Recommendation catalog.

Analyzers detect evidence.

This catalog maps analyzer finding types to reusable
recommendation families and variants.

Responsibilities:
    finding_type
        -> recommendation family
        -> recommendation variant
        -> recommendation scope

The catalog does NOT decide whether a finding is eligible.
Eligibility remains owned by the analyzer finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ======================================================================
# VALID SCOPES
# ======================================================================

VALID_RECOMMENDATION_SCOPES = frozenset(
    {
        "resource",
        "region",
        "account",
        "service",
    }
)


# ======================================================================
# MODELS
# ======================================================================

@dataclass(frozen=True, slots=True)
class RecommendationVariant:

    key: str

    title: str

    action: str

    reason: str = ""


@dataclass(frozen=True, slots=True)
class RecommendationDefinition:

    key: str

    title: str

    category: str

    default_action: str

    description: str = ""

    recommendation_scope: str = "region"

    variants: dict[str, RecommendationVariant] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:

        scope = str(
            self.recommendation_scope
            or "region"
        ).strip().lower()

        if scope not in VALID_RECOMMENDATION_SCOPES:
            raise ValueError(
                f"Invalid recommendation scope "
                f"{scope!r} for {self.key!r}."
            )

        for variant_key, variant in self.variants.items():

            if variant_key != variant.key:
                raise ValueError(
                    f"Variant key mismatch for "
                    f"{self.key!r}: "
                    f"{variant_key!r} != {variant.key!r}."
                )

            if not variant.title.strip():
                raise ValueError(
                    f"Variant {variant_key!r} "
                    f"in {self.key!r} has empty title."
                )

            if not variant.action.strip():
                raise ValueError(
                    f"Variant {variant_key!r} "
                    f"in {self.key!r} has empty action."
                )


@dataclass(frozen=True, slots=True)
class RecommendationRoute:

    recommendation_key: str

    variant_key: str | None = None


# ======================================================================
# CATALOG
# ======================================================================

CATALOG: dict[
    str,
    RecommendationDefinition,
] = {

    # ==================================================================
    # UNUSED RESOURCE
    # ==================================================================

    "review_unused_resource":
        RecommendationDefinition(
            key="review_unused_resource",

            title="Review potentially unused resource",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Resource evidence indicates possible unnecessary "
                "retention."
            ),

            default_action=(
                "Validate whether the resource is still required. "
                "Review workload dependencies, scheduled workloads, "
                "failover, recovery, and operational requirements "
                "before stopping, detaching, or removing it."
            ),

            variants={

                "rds_stopped":
                    RecommendationVariant(
                        key="rds_stopped",

                        title="Review stopped RDS instances",

                        reason=(
                            "{count} RDS instance{plural} "
                            "are currently stopped."
                        ),

                        action=(
                            "Validate application, storage, backup, "
                            "recovery, restart, and cluster requirements "
                            "before removing the instance."
                        ),
                    ),

                "rds_idle":
                    RecommendationVariant(
                        key="rds_idle",

                        title="Review idle RDS instances",

                        reason=(
                            "{count} RDS instance{plural} "
                            "showed very low observed activity."
                        ),

                        action=(
                            "Review workload, recovery, and cluster "
                            "requirements before stopping, resizing, "
                            "or removing the instance."
                        ),
                    ),

                "rds_read_replica":
                    RecommendationVariant(
                        key="rds_read_replica",

                        title="Review underused RDS read replicas",

                        reason=(
                            "{count} RDS read replica{plural} "
                            "showed low-utilization evidence."
                        ),

                        action=(
                            "Review replica workload and failover "
                            "requirements before resizing or removing it."
                        ),
                    ),

                "eks_no_workers":
                    RecommendationVariant(
                        key="eks_no_workers",

                        title="Review EKS clusters without worker capacity",

                        reason=(
                            "{count} EKS cluster{plural} "
                            "have no discovered worker capacity."
                        ),

                        action=(
                            "Validate whether the cluster is intentionally "
                            "empty or temporarily scaled to zero before "
                            "changing or removing it."
                        ),
                    ),

                "elb_no_activity":
                    RecommendationVariant(
                        key="elb_no_activity",

                        title="Review inactive load balancers",

                        reason=(
                            "{count} load balancer{plural} "
                            "showed no observed activity."
                        ),

                        action=(
                            "Validate listeners, target groups, scheduled "
                            "traffic, failover, and application dependencies "
                            "before removing or consolidating the load balancer."
                        ),
                    ),

                "elb_low_traffic":
                    RecommendationVariant(
                        key="elb_low_traffic",

                        title="Review low-traffic load balancers",

                        reason=(
                            "{count} load balancer{plural} "
                            "showed low observed traffic."
                        ),

                        action=(
                            "Review traffic patterns, scheduled workloads, "
                            "and application requirements before resizing "
                            "or consolidating the load balancer."
                        ),
                    ),

                "elb_no_targets":
                    RecommendationVariant(
                        key="elb_no_targets",

                        title="Review load balancers without targets",

                        reason=(
                            "{count} load balancer{plural} "
                            "have no registered targets."
                        ),

                        action=(
                            "Validate whether the load balancer is still "
                            "required before removing or consolidating it."
                        ),
                    ),

                "elb_no_healthy_targets":
                    RecommendationVariant(
                        key="elb_no_healthy_targets",

                        title=(
                            "Review load balancers without healthy targets"
                        ),

                        reason=(
                            "{count} load balancer{plural} "
                            "have no healthy targets."
                        ),

                        action=(
                            "Validate target health, application "
                            "dependencies, and failover requirements "
                            "before changing the load balancer."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # RIGHTSIZING
    # ==================================================================

    "review_rightsizing":
        RecommendationDefinition(
            key="review_rightsizing",

            title="Review resource rightsizing",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Utilization evidence indicates possible over-sizing."
            ),

            default_action=(
                "Review sustained utilization and compatible lower-cost "
                "capacity options before changing capacity."
            ),

            variants={

                "rds_utilization":
                    RecommendationVariant(
                        key="rds_utilization",

                        title="Review RDS rightsizing",

                        reason=(
                            "{count} RDS instance{plural} "
                            "show utilization evidence that "
                            "warrants rightsizing review."
                        ),

                        action=(
                            "Review CPU, connections, I/O, storage, "
                            "engine, and cluster requirements before "
                            "reducing capacity."
                        ),
                    ),

                "eks_workers":
                    RecommendationVariant(
                        key="eks_workers",

                        title="Review EKS worker capacity",

                        reason=(
                            "{count} EKS cluster{plural} "
                            "show low worker utilization."
                        ),

                        action=(
                            "Review worker CPU and memory usage, "
                            "workload peaks, and scheduling constraints "
                            "before reducing capacity."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # CAPACITY
    # ==================================================================

    "review_capacity_configuration":
        RecommendationDefinition(
            key="review_capacity_configuration",

            title="Review capacity configuration",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Capacity or scaling configuration may be inefficient."
            ),

            default_action=(
                "Compare configured capacity with demand and validate "
                "peaks, availability, and recovery requirements before "
                "changing it."
            ),

            variants={

                "eks_scaling":
                    RecommendationVariant(
                        key="eks_scaling",

                        title="Review EKS scaling headroom",

                        reason=(
                            "{count} EKS cluster{plural} "
                            "have scaling capacity that warrants review."
                        ),

                        action=(
                            "Review scaling limits against observed "
                            "and expected demand before reducing headroom."
                        ),
                    ),

                "eks_reserved":
                    RecommendationVariant(
                        key="eks_reserved",

                        title="Review EKS reserved capacity",

                        reason=(
                            "{count} EKS cluster{plural} "
                            "have reserved worker capacity "
                            "that warrants review."
                        ),

                        action=(
                            "Review pod requests, scheduling constraints, "
                            "and worker capacity before reducing it."
                        ),
                    ),

                "rds_io_pressure":
                    RecommendationVariant(
                        key="rds_io_pressure",

                        title="Review RDS I/O capacity",

                        reason=(
                            "{count} RDS instance{plural} "
                            "show I/O pressure evidence."
                        ),

                        action=(
                            "Review I/O workload, latency, IOPS, "
                            "throughput, and storage configuration "
                            "before changing capacity."
                        ),
                    ),

                "rds_io_latency":
                    RecommendationVariant(
                        key="rds_io_latency",

                        title="Review RDS I/O latency configuration",

                        reason=(
                            "{count} RDS instance{plural} "
                            "show elevated I/O latency."
                        ),

                        action=(
                            "Review storage performance requirements "
                            "and I/O workload before changing capacity."
                        ),
                    ),

                "rds_instance_class":
                    RecommendationVariant(
                        key="rds_instance_class",

                        title="Review RDS instance class",

                        reason=(
                            "{count} RDS instance{plural} "
                            "have instance-class configuration "
                            "that warrants review."
                        ),

                        action=(
                            "Compare sustained workload demand with "
                            "compatible instance classes before changing "
                            "capacity."
                        ),
                    ),

                "rds_storage_pressure":
                    RecommendationVariant(
                        key="rds_storage_pressure",

                        title="Review RDS storage capacity",

                        reason=(
                            "{count} RDS instance{plural} "
                            "show storage-capacity pressure."
                        ),

                        action=(
                            "Review storage growth, free space, "
                            "performance requirements, and scaling "
                            "configuration before changing capacity."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # NETWORK RESOURCE
    # ==================================================================

    "review_network_resource":
        RecommendationDefinition(
            key="review_network_resource",

            title="Review network resource usage",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "A network resource may be unnecessarily retained."
            ),

            default_action=(
                "Review active dependencies, attachments, routes, "
                "traffic, scheduled workloads, and failover requirements "
                "before removing or consolidating the network resource."
            ),

            variants={

                "nat_idle":
                    RecommendationVariant(
                        key="nat_idle",

                        title="Review potentially idle NAT Gateways",

                        reason=(
                            "{count} NAT Gateway{plural} "
                            "showed no observed traffic or connection "
                            "activity during the analysis period."
                        ),

                        action=(
                            "Validate dependent routes, workloads, "
                            "scheduled traffic, and failover requirements "
                            "before removing or consolidating the NAT Gateway."
                        ),
                    ),

                "nat_low_traffic":
                    RecommendationVariant(
                        key="nat_low_traffic",

                        title="Review low-traffic NAT Gateways",

                        reason=(
                            "{count} NAT Gateway{plural} "
                            "show low observed traffic."
                        ),

                        action=(
                            "Review workload traffic, scheduled activity, "
                            "routing, and availability requirements before "
                            "consolidating or changing the NAT Gateway."
                        ),
                    ),

                "tgw_no_attachments":
                    RecommendationVariant(
                        key="tgw_no_attachments",

                        title="Review Transit Gateways with no attachments",

                        reason=(
                            "{count} Transit Gateway{plural} "
                            "have no discovered attachments."
                        ),

                        action=(
                            "Validate whether each Transit Gateway "
                            "is still required before removing it."
                        ),
                    ),

                "tgw_no_traffic":
                    RecommendationVariant(
                        key="tgw_no_traffic",

                        title=(
                            "Review Transit Gateways with no observed traffic"
                        ),

                        reason=(
                            "{count} Transit Gateway{plural} "
                            "have active attachments but no observed "
                            "traffic during the analysis period."
                        ),

                        action=(
                            "Validate scheduled, intermittent, and "
                            "failover workloads before considering removal."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # NETWORK PATH
    # ==================================================================

    "review_network_path":
        RecommendationDefinition(
            key="review_network_path",

            title="Review network path optimization",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Observed workload and topology indicate a potentially "
                "inefficient network path."
            ),

            default_action=(
                "Review routing and dependencies for a more direct "
                "or lower-cost path before changing the network."
            ),

            variants={

                "nat_cross_az":
                    RecommendationVariant(
                        key="nat_cross_az",

                        title="Review cross-AZ NAT routing",

                        reason=(
                            "{count} NAT Gateway{plural} "
                            "have observed activity and dependent "
                            "subnets in another Availability Zone."
                        ),

                        action=(
                            "Review subnet-to-NAT routing and determine "
                            "whether same-AZ NAT placement can reduce "
                            "cross-AZ dependency without harming "
                            "availability or failover."
                        ),
                    ),

                "nat_endpoint":
                    RecommendationVariant(
                        key="nat_endpoint",

                        title="Review NAT-to-VPC-endpoint opportunities",

                        reason=(
                            "{count} NAT Gateway{plural} "
                            "have explicit observed AWS service traffic "
                            "for which endpoint coverage was not found."
                        ),

                        action=(
                            "Validate the affected AWS service, endpoint "
                            "type, route coverage, and application "
                            "dependencies before changing the path."
                        ),
                    ),

                "tgw_unrouted":
                    RecommendationVariant(
                        key="tgw_unrouted",

                        title="Review unrouted Transit Gateway attachments",

                        reason=(
                            "{count} Transit Gateway attachment{plural} "
                            "have no discovered VPC-side route."
                        ),

                        action=(
                            "Review the affected routes and confirm "
                            "the intended Transit Gateway architecture."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # NETWORK CONFIGURATION
    # ==================================================================

    "review_network_configuration":
        RecommendationDefinition(
            key="review_network_configuration",

            title="Review network configuration",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Network configuration requires review."
            ),

            default_action=(
                "Review routes, associations, attachments, and "
                "dependencies before correcting configuration."
            ),

            variants={

                "tgw_unassociated":
                    RecommendationVariant(
                        key="tgw_unassociated",

                        title=(
                            "Review unassociated Transit Gateway attachments"
                        ),

                        reason=(
                            "{count} Transit Gateway attachment{plural} "
                            "have no route-table association."
                        ),

                        action=(
                            "Review affected associations and confirm "
                            "the intended Transit Gateway routing design."
                        ),
                    ),

                "tgw_blackhole":
                    RecommendationVariant(
                        key="tgw_blackhole",

                        title=(
                            "Review Transit Gateway blackhole routes"
                        ),

                        reason=(
                            "{count} Transit Gateway route{plural} "
                            "are in blackhole state."
                        ),

                        action=(
                            "Review affected destinations and targets "
                            "and correct obsolete routing where required."
                        ),
                    ),

                "tgw_vpc_blackhole":
                    RecommendationVariant(
                        key="tgw_vpc_blackhole",

                        title=(
                            "Review VPC blackhole routes to Transit Gateway"
                        ),

                        reason=(
                            "{count} VPC route{plural} "
                            "targeting the Transit Gateway are blackholed."
                        ),

                        action=(
                            "Review the affected VPC routes and correct "
                            "obsolete routing where required."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # PUBLIC IPV4
    # ==================================================================

    "review_public_ip":
        RecommendationDefinition(
            key="review_public_ip",

            title="Review public IPv4 usage",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Public IPv4 usage is explicitly eligible for review."
            ),

            default_action=(
                "Release an unassociated public IPv4 only after "
                "validating DNS, failover, migration, application, "
                "and future workload requirements."
            ),

            variants={

                "unassociated":
                    RecommendationVariant(
                        key="unassociated",

                        title=(
                            "Review unassociated public IPv4 addresses"
                        ),

                        reason=(
                            "{count} public IPv4 resource{plural} "
                            "are explicitly unassociated."
                        ),

                        action=(
                            "Release the address only after validating "
                            "DNS, failover, migration, application, "
                            "and future requirements."
                        ),
                    ),

                "stopped_instance":
                    RecommendationVariant(
                        key="stopped_instance",

                        title=(
                            "Review public IPv4 addresses on stopped EC2"
                        ),

                        reason=(
                            "{count} public IPv4 resource{plural} "
                            "are associated with stopped EC2 instances."
                        ),

                        action=(
                            "Validate instance lifecycle and future "
                            "requirements before releasing the address."
                        ),
                    ),
            },
        ),

    # ==================================================================
    # BACKUP
    # ==================================================================

    "review_backup_configuration":
        RecommendationDefinition(
            key="review_backup_configuration",

            title="Review backup configuration",

            category="cost_optimization",

            recommendation_scope="region",

            description=(
                "Backup retention may be higher than required."
            ),

            default_action=(
                "Review retention against recovery and compliance "
                "requirements before reducing it."
            ),

            variants={

                "retention":
                    RecommendationVariant(
                        key="retention",

                        title="Review backup retention",

                        reason=(
                            "{count} resource{plural} "
                            "have backup-retention configuration "
                            "that warrants review."
                        ),

                        action=(
                            "Review retention against recovery and "
                            "compliance requirements before reducing it."
                        ),
                    ),
            },
        ),
}


# ======================================================================
# FINDING -> ROUTE
# ======================================================================

FINDING_TO_RECOMMENDATION: dict[
    str,
    RecommendationRoute,
] = {

    # NAT
    "nat_gateway_idle":
        RecommendationRoute(
            "review_network_resource",
            "nat_idle",
        ),

    "nat_gateway_low_traffic":
        RecommendationRoute(
            "review_network_resource",
            "nat_low_traffic",
        ),

    "nat_gateway_cross_az":
        RecommendationRoute(
            "review_network_path",
            "nat_cross_az",
        ),

    "nat_gateway_aws_service_traffic":
        RecommendationRoute(
            "review_network_path",
            "nat_endpoint",
        ),

    "nat_gateway_endpoint_opportunity":
        RecommendationRoute(
            "review_network_path",
            "nat_endpoint",
        ),

    # RDS
    "rds_stopped_instance":
        RecommendationRoute(
            "review_unused_resource",
            "rds_stopped",
        ),

    "rds_idle_instance":
        RecommendationRoute(
            "review_unused_resource",
            "rds_idle",
        ),

    "rds_low_utilization":
        RecommendationRoute(
            "review_rightsizing",
            "rds_utilization",
        ),

    "rds_memory_pressure":
        RecommendationRoute(
            "review_rightsizing",
            "rds_utilization",
        ),

    "rds_provisioned_iops_underuse":
        RecommendationRoute(
            "review_rightsizing",
            "rds_utilization",
        ),

    "rds_underused_read_replica":
        RecommendationRoute(
            "review_unused_resource",
            "rds_read_replica",
        ),

    "rds_backup_retention_review":
        RecommendationRoute(
            "review_backup_configuration",
            "retention",
        ),

    "rds_io_pressure":
        RecommendationRoute(
            "review_capacity_configuration",
            "rds_io_pressure",
        ),

    "rds_io_latency":
        RecommendationRoute(
            "review_capacity_configuration",
            "rds_io_latency",
        ),

    "rds_instance_class_changes":
        RecommendationRoute(
            "review_capacity_configuration",
            "rds_instance_class",
        ),

    "rds_storage_pressure":
        RecommendationRoute(
            "review_capacity_configuration",
            "rds_storage_pressure",
        ),

    # EKS
    "eks_no_worker_capacity":
        RecommendationRoute(
            "review_unused_resource",
            "eks_no_workers",
        ),

    "eks_low_worker_utilization":
        RecommendationRoute(
            "review_rightsizing",
            "eks_workers",
        ),

    "eks_excessive_scaling_headroom":
        RecommendationRoute(
            "review_capacity_configuration",
            "eks_scaling",
        ),

    "eks_high_reserved_capacity":
        RecommendationRoute(
            "review_capacity_configuration",
            "eks_reserved",
        ),

    # ELB
    "elb_no_observed_activity":
        RecommendationRoute(
            "review_unused_resource",
            "elb_no_activity",
        ),

    "elb_low_traffic":
        RecommendationRoute(
            "review_unused_resource",
            "elb_low_traffic",
        ),

    "elb_no_registered_targets":
        RecommendationRoute(
            "review_unused_resource",
            "elb_no_targets",
        ),

    "elb_idle_target_group":
        RecommendationRoute(
            "review_unused_resource",
            "elb_no_activity",
        ),

    "elb_no_healthy_targets_no_traffic":
        RecommendationRoute(
            "review_unused_resource",
            "elb_no_healthy_targets",
        ),

    # TRANSIT GATEWAY
    "transit_gateway_no_attachments":
        RecommendationRoute(
            "review_network_resource",
            "tgw_no_attachments",
        ),

    "transit_gateway_no_observed_traffic":
        RecommendationRoute(
            "review_network_resource",
            "tgw_no_traffic",
        ),

    "transit_gateway_unrouted_attachment":
        RecommendationRoute(
            "review_network_path",
            "tgw_unrouted",
        ),

    "transit_gateway_unassociated_attachment":
        RecommendationRoute(
            "review_network_configuration",
            "tgw_unassociated",
        ),

    "transit_gateway_blackhole_routes":
        RecommendationRoute(
            "review_network_configuration",
            "tgw_blackhole",
        ),

    "transit_gateway_vpc_blackhole_routes":
        RecommendationRoute(
            "review_network_configuration",
            "tgw_vpc_blackhole",
        ),

    # PUBLIC IPV4
    "elastic_ip_unassociated":
        RecommendationRoute(
            "review_public_ip",
            "unassociated",
        ),

    "elastic_ip_on_stopped_instance":
        RecommendationRoute(
            "review_public_ip",
            "stopped_instance",
        ),
}


# ======================================================================
# VALIDATION
# ======================================================================

def validate_catalog() -> None:

    for key, definition in CATALOG.items():

        if key != definition.key:
            raise ValueError(
                f"Catalog key mismatch: "
                f"{key!r} != {definition.key!r}."
            )

        scope = str(
            definition.recommendation_scope
            or "region"
        ).strip().lower()

        if scope not in VALID_RECOMMENDATION_SCOPES:
            raise ValueError(
                f"Invalid scope for {key!r}: {scope!r}"
            )

        for variant_key, variant in definition.variants.items():

            if variant.key != variant_key:
                raise ValueError(
                    f"Variant key mismatch for "
                    f"{key!r}: {variant_key!r}"
                )

    for finding_type, route in FINDING_TO_RECOMMENDATION.items():

        if not finding_type.strip():
            raise ValueError(
                "Finding route contains an empty finding type."
            )

        definition = CATALOG.get(
            route.recommendation_key
        )

        if definition is None:
            raise ValueError(
                f"{finding_type!r} maps to unknown "
                f"recommendation {route.recommendation_key!r}."
            )

        if route.variant_key is not None:
            if route.variant_key not in definition.variants:
                raise ValueError(
                    f"{finding_type!r} references unknown "
                    f"variant {route.variant_key!r}."
                )


validate_catalog()


# ======================================================================
# LOOKUPS
# ======================================================================

def _finding_type(
    finding: dict[str, Any],
) -> str | None:

    if not isinstance(finding, dict):
        return None

    value = (
        finding.get("finding_type")
        or finding.get("finding_key")
    )

    if not value:
        return None

    text = str(value).strip()

    return text or None


def recommendation_route_for_finding(
    finding: dict[str, Any],
) -> RecommendationRoute | None:

    finding_type = _finding_type(finding)

    if not finding_type:
        return None

    return FINDING_TO_RECOMMENDATION.get(
        finding_type
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

    if not recommendation_key:
        return None

    return CATALOG.get(
        str(recommendation_key).strip()
    )


def get_variant(
    recommendation_key: str,
    variant_key: str | None,
) -> RecommendationVariant | None:

    if not recommendation_key or not variant_key:
        return None

    definition = get_definition(
        recommendation_key
    )

    if definition is None:
        return None

    return definition.variants.get(
        variant_key
    )


def is_supported_recommendation_key(
    recommendation_key: str,
) -> bool:

    return bool(
        recommendation_key
        and str(recommendation_key).strip()
        in CATALOG
    )