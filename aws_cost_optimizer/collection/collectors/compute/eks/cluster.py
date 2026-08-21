"""
Amazon EKS collector.

Purpose
-------
Collect cost-optimization evidence for Amazon EKS without making
optimization decisions.

The collector separates:

    cluster metrics
        ClusterName

    node metrics
        ClusterName + InstanceId + NodeName

    pod metrics
        ClusterName + Namespace + PodName

CloudWatch series are never collapsed solely by metric name.

Evidence collected:

Cluster
-------
- identity
- Kubernetes version
- cluster status
- control-plane configuration
- networking
- encryption
- logging
- addons
- deletion protection

Compute
-------
- managed node groups
- scaling configuration
- instance types
- capacity type
- launch template
- AMI type
- node-group health
- EC2 worker instances
- attached EBS volumes
- ENIs
- security groups
- Fargate profiles

CloudWatch / Container Insights
--------------------------------
Cluster:
- cluster_node_count
- cluster_failed_node_count

Node:
- node_cpu_utilization
- node_cpu_limit
- node_cpu_reserved_capacity
- node_cpu_usage_total
- node_memory_utilization
- node_memory_limit
- node_memory_reserved_capacity
- node_memory_working_set
- node_filesystem_utilization
- node_network_total_bytes
- node_number_of_running_pods
- node_number_of_running_containers
- node_gpu_limit
- node_gpu_usage_total
- node_gpu_reserved_capacity
- node_gpu_utilization

Pod:
- pod_cpu_utilization
- pod_cpu_utilization_over_pod_limit
- pod_cpu_reserved_capacity
- pod_memory_utilization
- pod_memory_utilization_over_pod_limit
- pod_memory_reserved_capacity
- pod_memory_working_set
- pod_gpu_limit
- pod_gpu_usage_total
- pod_gpu_reserved_capacity
- pod_gpu_utilization

The analyzer decides whether these signals represent a
cost-optimization opportunity.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from aws_cost_optimizer.config.client import get_client

from ....base import BaseCollector
from ....registry import register

from ....metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from ....shared.topology import (
    NetworkTopologyCollector,
)


@register
class EksCollector(BaseCollector):

    key = "eks"
    resource_type = "eks_cluster"

    DEFAULT_NAMESPACE = "ContainerInsights"
    DEFAULT_PERIOD_SECONDS = 3600

    # CloudWatch ListMetrics is used to discover actual metric
    # dimension combinations.
    #
    # These are the dimension combinations supported by the
    # Container Insights metric families we use.
    NODE_DIMENSIONS = (
        "ClusterName",
        "InstanceId",
        "NodeName",
    )

    POD_DIMENSIONS = (
        "ClusterName",
        "Namespace",
        "PodName",
    )

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: dict | None = None,
    ):
        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        self.eks = get_client(
            "eks",
            self.region,
        )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = (
            CloudWatchMetricCollector(
                self.cloudwatch
            )
        )

        self.topology_collector = (
            NetworkTopologyCollector(
                self.region
            )
        )

        # ClusterName -> collected CloudWatch series.
        #
        # Each item keeps:
        #
        #   metric_name
        #   metric_key
        #   dimensions
        #   values / summary
        #
        # This prevents node/pod series from overwriting each other.
        self._metrics_batch_cache: Dict[
            str,
            Dict[str, Any],
        ] = {}

        self._metric_dimension_cache: Dict[
            Tuple[str, str, str],
            List[List[Dict[str, str]]],
        ] = {}

    # ==================================================================
    # PROFILE
    # ==================================================================

    def _profile_section(
        self,
        name: str,
    ) -> Dict[str, Any]:

        if not isinstance(
            self.profile,
            dict,
        ):
            return {}

        value = self.profile.get(
            name,
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> Dict[str, Any]:

        observations = self._profile_section(
            "observations"
        )

        value = observations.get(
            "cloudwatch",
            {},
        )

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    def _metric_specs(
        self,
        name: str,
    ) -> List[Dict[str, Any]]:

        values = (
            self._cloudwatch_profile().get(
                name,
                [],
            )
        )

        if not isinstance(
            values,
            list,
        ):
            return []

        return [
            value
            for value in values
            if isinstance(
                value,
                dict,
            )
        ]

    def _namespace(self) -> str:

        return str(
            self._cloudwatch_profile().get(
                "namespace",
                self.DEFAULT_NAMESPACE,
            )
        ).strip()

    def _requested_period(self) -> int:

        try:
            return int(
                self._cloudwatch_profile().get(
                    "period",
                    self.DEFAULT_PERIOD_SECONDS,
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            return self.DEFAULT_PERIOD_SECONDS

    # ==================================================================
    # DISCOVERY
    # ==================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        clusters: List[
            Dict[str, Any]
        ] = []

        paginator = self.eks.get_paginator(
            "list_clusters"
        )

        for page in paginator.paginate():

            for cluster_name in page.get(
                "clusters",
                [],
            ):

                if not cluster_name:
                    continue

                try:

                    response = (
                        self.eks.describe_cluster(
                            name=cluster_name
                        )
                    )

                    cluster = response.get(
                        "cluster"
                    )

                    if cluster:
                        clusters.append(
                            cluster
                        )

                except Exception as exc:

                    print(
                        f"[EKS] Failed to describe "
                        f"{cluster_name}: {exc}"
                    )

        self._prefetch_metrics(
            clusters
        )

        return clusters

    # ==================================================================
    # CLOUDWATCH PREFETCH
    # ==================================================================

    def _prefetch_metrics(
        self,
        clusters: List[Dict[str, Any]],
    ) -> None:

        if not clusters:
            return

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if not cloudwatch_profile:
            return

        if (
            cloudwatch_profile.get(
                "enabled",
                True,
            )
            is False
        ):
            return

        try:

            start, end = (
                self.get_analysis_period()
            )

        except Exception as exc:

            print(
                f"[EKS] CloudWatch analysis period "
                f"unavailable: {exc}"
            )

            return

        namespace = self._namespace()

        cluster_specs = (
            self._metric_specs(
                "cluster_metrics"
            )
        )

        node_specs = (
            self._metric_specs(
                "node_metrics"
            )
        )

        pod_specs = (
            self._metric_specs(
                "pod_metrics"
            )
        )

        for cluster in clusters:

            cluster_name = (
                cluster.get("name")
            )

            if not cluster_name:
                continue

            result = {
                "cluster": [],
                "nodes": [],
                "pods": [],
            }

            # ----------------------------------------------------------
            # Cluster metrics
            # ----------------------------------------------------------

            if cluster_specs:

                requests = [
                    {
                        "resource_key":
                            self._series_key(
                                cluster_name,
                                "cluster",
                                index,
                                spec,
                            ),

                        "namespace":
                            namespace,

                        "dimensions": [
                            {
                                "Name":
                                    "ClusterName",

                                "Value":
                                    cluster_name,
                            }
                        ],

                        "metric_specs":
                            [spec],
                    }
                    for index, spec
                    in enumerate(
                        cluster_specs
                    )
                ]

                response = (
                    self.metric_collector.collect_batch(
                        requests,
                        start=start,
                        end=end,
                        requested_period=(
                            self._requested_period()
                        ),
                    )
                )

                for series in response.values():

                    if not series:
                        continue

                    result["cluster"].extend(
                        series
                    )

            # ----------------------------------------------------------
            # Node metrics
            # ----------------------------------------------------------

            for index, spec in enumerate(
                node_specs
            ):

                metric_name = str(
                    spec.get(
                        "name",
                        "",
                    )
                ).strip()

                if not metric_name:
                    continue

                dimension_sets = (
                    self._discover_metric_dimensions(
                        namespace=namespace,
                        metric_name=metric_name,
                        cluster_name=cluster_name,
                        group="node",
                    )
                )

                # IMPORTANT: do not fall back to a ClusterName-only
                # dimension set when node identity discovery fails.
                # A metric collected only by ClusterName is a
                # cluster-wide aggregate, not a node series -- treating
                # it as one would fabricate node-level evidence that
                # was never actually observed at node granularity.
                if not dimension_sets:
                    continue

                requests = []

                for series_index, dimensions in enumerate(
                    dimension_sets
                ):

                    requests.append(
                        {
                            "resource_key":
                                self._series_key(
                                    cluster_name,
                                    "node",
                                    (
                                        index,
                                        series_index,
                                    ),
                                    spec,
                                ),

                            "namespace":
                                namespace,

                            "dimensions":
                                dimensions,

                            "metric_specs":
                                [spec],
                        }
                    )

                if requests:

                    response = (
                        self.metric_collector.collect_batch(
                            requests,
                            start=start,
                            end=end,
                            requested_period=(
                                self._requested_period()
                            ),
                        )
                    )

                    for series in response.values():

                        if series:
                            result["nodes"].extend(
                                series
                            )

            # ----------------------------------------------------------
            # Pod metrics
            # ----------------------------------------------------------

            for index, spec in enumerate(
                pod_specs
            ):

                metric_name = str(
                    spec.get(
                        "name",
                        "",
                    )
                ).strip()

                if not metric_name:
                    continue

                dimension_sets = (
                    self._discover_metric_dimensions(
                        namespace=namespace,
                        metric_name=metric_name,
                        cluster_name=cluster_name,
                        group="pod",
                    )
                )

                # IMPORTANT: do not fall back to a ClusterName-only
                # dimension set when pod identity discovery fails.
                # A metric collected only by ClusterName is a
                # cluster-wide aggregate, not a pod series -- treating
                # it as one would fabricate pod-level evidence that
                # was never actually observed at pod granularity.
                if not dimension_sets:
                    continue

                requests = []

                for series_index, dimensions in enumerate(
                    dimension_sets
                ):

                    requests.append(
                        {
                            "resource_key":
                                self._series_key(
                                    cluster_name,
                                    "pod",
                                    (
                                        index,
                                        series_index,
                                    ),
                                    spec,
                                ),

                            "namespace":
                                namespace,

                            "dimensions":
                                dimensions,

                            "metric_specs":
                                [spec],
                        }
                    )

                if requests:

                    response = (
                        self.metric_collector.collect_batch(
                            requests,
                            start=start,
                            end=end,
                            requested_period=(
                                self._requested_period()
                            ),
                        )
                    )

                    for series in response.values():

                        if series:
                            result["pods"].extend(
                                series
                            )

            self._metrics_batch_cache[
                cluster_name
            ] = result

    def _discover_metric_dimensions(
        self,
        *,
        namespace: str,
        metric_name: str,
        cluster_name: str,
        group: str,
    ) -> List[
        List[Dict[str, str]]
    ]:

        cache_key = (
            namespace,
            metric_name,
            f"{group}:{cluster_name}",
        )

        cached = (
            self._metric_dimension_cache.get(
                cache_key
            )
        )

        if cached is not None:
            return cached

        expected_dimensions = (
            self.NODE_DIMENSIONS
            if group == "node"
            else self.POD_DIMENSIONS
        )

        dimensions_sets: List[
            List[Dict[str, str]]
        ] = []

        try:

            paginator = (
                self.cloudwatch.get_paginator(
                    "list_metrics"
                )
            )

            for page in paginator.paginate(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[
                    {
                        "Name":
                            "ClusterName",

                        "Value":
                            cluster_name,
                    }
                ],
            ):

                for metric in page.get(
                    "Metrics",
                    [],
                ):

                    raw_dimensions = (
                        metric.get(
                            "Dimensions",
                            [],
                        )
                    )

                    if not isinstance(
                        raw_dimensions,
                        list,
                    ):
                        continue

                    normalized = []

                    for dimension in (
                        raw_dimensions
                    ):

                        if not isinstance(
                            dimension,
                            dict,
                        ):
                            continue

                        name = dimension.get(
                            "Name"
                        )

                        value = dimension.get(
                            "Value"
                        )

                        if not name or value is None:
                            continue

                        normalized.append(
                            {
                                "Name":
                                    str(name),

                                "Value":
                                    str(value),
                            }
                        )

                    names = {
                        item["Name"]
                        for item in normalized
                    }

                    if not all(
                        required in names
                        for required
                        in expected_dimensions
                    ):
                        continue

                    # Keep exactly the expected identity dimensions.
                    #
                    # Extra dimensions can cause duplicate series,
                    # so we retain only the identity set relevant to
                    # this group.
                    selected = [
                        item
                        for item in normalized
                        if item["Name"]
                        in expected_dimensions
                    ]

                    selected.sort(
                        key=lambda item:
                            expected_dimensions.index(
                                item["Name"]
                            )
                    )

                    signature = tuple(
                        (
                            item["Name"],
                            item["Value"],
                        )
                        for item
                        in selected
                    )

                    existing_signatures = {
                        tuple(
                            (
                                item["Name"],
                                item["Value"],
                            )
                            for item
                            in existing
                        )
                        for existing
                        in dimensions_sets
                    }

                    if signature not in existing_signatures:
                        dimensions_sets.append(
                            selected
                        )

        except Exception as exc:

            print(
                f"[EKS] Failed to discover "
                f"CloudWatch dimensions for "
                f"{metric_name}: {exc}"
            )

        self._metric_dimension_cache[
            cache_key
        ] = dimensions_sets

        return dimensions_sets

    @staticmethod
    def _series_key(
        cluster_name: str,
        group: str,
        index: Any,
        spec: Dict[str, Any],
    ) -> str:

        metric_key = (
            spec.get("key")
            or spec.get("name")
            or "metric"
        )

        return (
            f"{cluster_name}:"
            f"{group}:"
            f"{index}:"
            f"{metric_key}"
        )

    # ==================================================================
    # RESOURCE ID
    # ==================================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = (
            resource.get("arn")
            or resource.get("name")
            or resource.get("id")
        )

        if not value:
            raise ValueError(
                "EKS cluster has no ARN or name"
            )

        return str(value)

    # ==================================================================
    # IDENTITY
    # ==================================================================

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "name":
                resource.get("name"),

            "arn":
                resource.get("arn"),

            "cluster_id":
                resource.get("id"),

            "status":
                resource.get("status"),

            "version":
                resource.get("version"),

            "platform_version":
                resource.get(
                    "platformVersion"
                ),

            "created_at":
                self._isoformat(
                    resource.get(
                        "createdAt"
                    )
                ),

            "tags":
                resource.get(
                    "tags",
                    {},
                ),

            "support_assessment": {
                "version":
                    resource.get(
                        "version"
                    ),

                # Deliberately not guessed.
                "support_type":
                    None,

                "support_status":
                    "requires_pricing_catalog_or_explicit_profile",
            },
        }

    # ==================================================================
    # CONFIGURATION
    # ==================================================================

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cluster_name = resource.get(
            "name"
        )

        vpc_config = (
            resource.get(
                "resourcesVpcConfig",
                {},
            )
            or {}
        )

        kubernetes_network = (
            resource.get(
                "kubernetesNetworkConfig",
                {},
            )
            or {}
        )

        access_config = (
            resource.get(
                "accessConfig",
                {},
            )
            or {}
        )

        return {
            "cluster": {
                "name":
                    resource.get("name"),

                "arn":
                    resource.get("arn"),

                "id":
                    resource.get("id"),

                "status":
                    resource.get("status"),

                "version":
                    resource.get("version"),

                "platform_version":
                    resource.get(
                        "platformVersion"
                    ),

                "created_at":
                    self._isoformat(
                        resource.get(
                            "createdAt"
                        )
                    ),

                "endpoint":
                    resource.get(
                        "endpoint"
                    ),

                "role_arn":
                    resource.get(
                        "roleArn"
                    ),

                "deletion_protection":
                    resource.get(
                        "deletionProtection"
                    ),

                "control_plane_scaling":
                    resource.get(
                        "controlPlaneScalingConfig",
                        {},
                    ),
            },

            "network": {
                "vpc_id":
                    vpc_config.get("vpcId"),

                "subnet_ids":
                    list(
                        vpc_config.get(
                            "subnetIds",
                            [],
                        )
                        or []
                    ),

                "security_group_ids":
                    list(
                        vpc_config.get(
                            "securityGroupIds",
                            [],
                        )
                        or []
                    ),

                "cluster_security_group_id":
                    vpc_config.get(
                        "clusterSecurityGroupId"
                    ),

                "endpoint_public_access":
                    vpc_config.get(
                        "endpointPublicAccess"
                    ),

                "endpoint_private_access":
                    vpc_config.get(
                        "endpointPrivateAccess"
                    ),

                "public_access_cidrs":
                    list(
                        vpc_config.get(
                            "publicAccessCidrs",
                            [],
                        )
                        or []
                    ),

                "ip_family":
                    kubernetes_network.get(
                        "ipFamily"
                    ),
            },

            "kubernetes_network": {
                "service_ipv4_cidr":
                    kubernetes_network.get(
                        "serviceIpv4Cidr"
                    ),

                "service_ipv6_cidr":
                    kubernetes_network.get(
                        "serviceIpv6Cidr"
                    ),
            },

            "access": {
                "authentication_mode":
                    access_config.get(
                        "authenticationMode"
                    ),

                "bootstrap_cluster_creator_admin_permissions":
                    access_config.get(
                        "bootstrapClusterCreatorAdminPermissions"
                    ),
            },

            "encryption":
                self._normalize_encryption(
                    resource.get(
                        "encryptionConfig",
                        [],
                    )
                ),

            "logging":
                resource.get(
                    "logging",
                    {},
                ),

            "compute":
                self._collect_compute(
                    cluster_name
                ),

            "addons":
                self._collect_addons(
                    cluster_name
                ),
        }

    # ==================================================================
    # COMPUTE
    # ==================================================================

    def _collect_compute(
        self,
        cluster_name: Optional[str],
    ) -> Dict[str, Any]:

        if not cluster_name:

            return {
                "inventory_status":
                    "incomplete",

                "inventory_errors": [
                    "Cluster name unavailable."
                ],

                "nodegroups": [],
                "fargate_profiles": [],
                "ec2_instances": [],

                "summary": {},
            }

        errors: List[str] = []

        nodegroups, nodegroup_errors = (
            self._collect_nodegroups(
                cluster_name
            )
        )

        errors.extend(
            nodegroup_errors
        )

        fargate_profiles, fargate_errors = (
            self._collect_fargate_profiles(
                cluster_name
            )
        )

        errors.extend(
            fargate_errors
        )

        ec2_instances, ec2_errors = (
            self._collect_ec2_instances(
                nodegroups
            )
        )

        errors.extend(
            ec2_errors
        )

        desired = 0
        minimum = 0
        maximum = 0

        for nodegroup in nodegroups:

            scaling = (
                nodegroup.get(
                    "scaling",
                    {},
                )
                or {}
            )

            desired += self._number_or_zero(
                scaling.get(
                    "desired_size"
                )
            )

            minimum += self._number_or_zero(
                scaling.get(
                    "min_size"
                )
            )

            maximum += self._number_or_zero(
                scaling.get(
                    "max_size"
                )
            )

        return {
            "inventory_status": (
                "complete"
                if not errors
                else "partial"
            ),

            "inventory_errors":
                errors,

            "nodegroups":
                nodegroups,

            "fargate_profiles":
                fargate_profiles,

            "ec2_instances":
                ec2_instances,

            "summary": {
                "nodegroup_count":
                    len(nodegroups),

                "fargate_profile_count":
                    len(
                        fargate_profiles
                    ),

                "ec2_instance_count":
                    len(
                        ec2_instances
                    ),

                "desired_node_count":
                    desired,

                "minimum_node_count":
                    minimum,

                "maximum_node_count":
                    maximum,
            },
        }

    # ==================================================================
    # NODE GROUPS
    # ==================================================================

    def _collect_nodegroups(
        self,
        cluster_name: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        errors: List[str] = []

        try:

            paginator = (
                self.eks.get_paginator(
                    "list_nodegroups"
                )
            )

            for page in paginator.paginate(
                clusterName=cluster_name
            ):

                for nodegroup_name in page.get(
                    "nodegroups",
                    [],
                ):

                    try:

                        response = (
                            self.eks.describe_nodegroup(
                                clusterName=cluster_name,
                                nodegroupName=nodegroup_name,
                            )
                        )

                        nodegroup = response.get(
                            "nodegroup",
                            {},
                        )

                        scaling = (
                            nodegroup.get(
                                "scalingConfig",
                                {},
                            )
                            or {}
                        )

                        update = (
                            nodegroup.get(
                                "updateConfig",
                                {},
                            )
                            or {}
                        )

                        resources = (
                            nodegroup.get(
                                "resources",
                                {},
                            )
                            or {}
                        )

                        health = (
                            nodegroup.get(
                                "health",
                                {},
                            )
                            or {}
                        )

                        launch_template = (
                            nodegroup.get(
                                "launchTemplate",
                                {},
                            )
                            or {}
                        )

                        result.append(
                            {
                                "name":
                                    nodegroup.get(
                                        "nodegroupName"
                                    ),

                                "arn":
                                    nodegroup.get(
                                        "nodegroupArn"
                                    ),

                                "status":
                                    nodegroup.get(
                                        "status"
                                    ),

                                "created_at":
                                    self._isoformat(
                                        nodegroup.get(
                                            "createdAt"
                                        )
                                    ),

                                "modified_at":
                                    self._isoformat(
                                        nodegroup.get(
                                            "modifiedAt"
                                        )
                                    ),

                                "instance_types":
                                    list(
                                        nodegroup.get(
                                            "instanceTypes",
                                            [],
                                        )
                                        or []
                                    ),

                                "capacity_type":
                                    nodegroup.get(
                                        "capacityType"
                                    ),

                                "ami_type":
                                    nodegroup.get(
                                        "amiType"
                                    ),

                                "disk_size_gib":
                                    nodegroup.get(
                                        "diskSize"
                                    ),

                                "subnets":
                                    list(
                                        nodegroup.get(
                                            "subnets",
                                            [],
                                        )
                                        or []
                                    ),

                                "node_role":
                                    nodegroup.get(
                                        "nodeRole"
                                    ),

                                "scaling": {
                                    "min_size":
                                        scaling.get(
                                            "minSize"
                                        ),

                                    "max_size":
                                        scaling.get(
                                            "maxSize"
                                        ),

                                    "desired_size":
                                        scaling.get(
                                            "desiredSize"
                                        ),
                                },

                                "update": {
                                    "max_unavailable":
                                        update.get(
                                            "maxUnavailable"
                                        ),

                                    "max_unavailable_percentage":
                                        update.get(
                                            "maxUnavailablePercentage"
                                        ),
                                },

                                "launch_template": {
                                    "id":
                                        launch_template.get(
                                            "id"
                                        ),

                                    "name":
                                        launch_template.get(
                                            "name"
                                        ),

                                    "version":
                                        launch_template.get(
                                            "version"
                                        ),
                                },

                                "resources": {
                                    "auto_scaling_groups":
                                        resources.get(
                                            "autoScalingGroups",
                                            [],
                                        ),

                                    "remote_access_security_group":
                                        resources.get(
                                            "remoteAccessSecurityGroup"
                                        ),
                                },

                                "health": {
                                    "issues":
                                        health.get(
                                            "issues",
                                            [],
                                        ),
                                },

                                "labels":
                                    nodegroup.get(
                                        "labels",
                                        {},
                                    ),

                                "taints":
                                    nodegroup.get(
                                        "taints",
                                        [],
                                    ),

                                "tags":
                                    nodegroup.get(
                                        "tags",
                                        {},
                                    ),
                            }
                        )

                    except Exception as exc:

                        errors.append(
                            (
                                "Failed to describe "
                                f"nodegroup "
                                f"{nodegroup_name}: "
                                f"{exc}"
                            )
                        )

        except Exception as exc:

            errors.append(
                (
                    "Failed to list nodegroups "
                    f"for {cluster_name}: {exc}"
                )
            )

        return result, errors

    # ==================================================================
    # EC2 WORKERS
    # ==================================================================

    def _collect_ec2_instances(
        self,
        nodegroups: List[Dict[str, Any]],
    ) -> Tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        errors: List[str] = []

        seen_instance_ids: set[str] = set()

        for nodegroup in nodegroups:

            resources = (
                nodegroup.get(
                    "resources",
                    {},
                )
                or {}
            )

            asgs = (
                resources.get(
                    "auto_scaling_groups",
                    [],
                )
                or []
            )

            if not isinstance(
                asgs,
                list,
            ):
                continue

            for asg in asgs:

                if not isinstance(
                    asg,
                    dict,
                ):
                    continue

                asg_name = asg.get(
                    "name"
                )

                if not asg_name:
                    continue

                try:

                    response = (
                        self.ec2
                        .describe_auto_scaling_groups(
                            AutoScalingGroupNames=[
                                asg_name
                            ]
                        )
                    )

                except Exception as exc:

                    errors.append(
                        (
                            f"Failed to inspect "
                            f"ASG {asg_name}: "
                            f"{exc}"
                        )
                    )

                    continue

                groups = response.get(
                    "AutoScalingGroups",
                    [],
                )

                for group in groups:

                    for instance in (
                        group.get(
                            "Instances",
                            [],
                        )
                        or []
                    ):

                        instance_id = instance.get(
                            "InstanceId"
                        )

                        if not instance_id:
                            continue

                        if (
                            instance_id
                            in seen_instance_ids
                        ):
                            continue

                        seen_instance_ids.add(
                            instance_id
                        )

                        try:

                            ec2_response = (
                                self.ec2
                                .describe_instances(
                                    InstanceIds=[
                                        instance_id
                                    ]
                                )
                            )

                        except Exception as exc:

                            errors.append(
                                (
                                    f"Failed to "
                                    f"describe EC2 "
                                    f"instance "
                                    f"{instance_id}: "
                                    f"{exc}"
                                )
                            )

                            continue

                        for reservation in (
                            ec2_response.get(
                                "Reservations",
                                [],
                            )
                        ):

                            for ec2_instance in (
                                reservation.get(
                                    "Instances",
                                    [],
                                )
                                or []
                            ):

                                result.append(
                                    self._instance_record(
                                        ec2_instance,
                                        nodegroup,
                                        asg_name,
                                    )
                                )

        return result, errors

    def _instance_record(
        self,
        instance: Dict[str, Any],
        nodegroup: Dict[str, Any],
        asg_name: str,
    ) -> Dict[str, Any]:

        state = (
            instance.get(
                "State",
                {},
            )
            or {}
        )

        placement = (
            instance.get(
                "Placement",
                {},
            )
            or {}
        )

        block_devices = []

        for device in (
            instance.get(
                "BlockDeviceMappings",
                [],
            )
            or []
        ):

            if not isinstance(
                device,
                dict,
            ):
                continue

            ebs = (
                device.get(
                    "Ebs",
                    {},
                )
                or {}
            )

            if not ebs:
                continue

            block_devices.append(
                {
                    "device_name":
                        device.get(
                            "DeviceName"
                        ),

                    "volume_id":
                        ebs.get(
                            "VolumeId"
                        ),

                    "delete_on_termination":
                        ebs.get(
                            "DeleteOnTermination"
                        ),
                }
            )

        network_interfaces = []

        for eni in (
            instance.get(
                "NetworkInterfaces",
                [],
            )
            or []
        ):

            if not isinstance(
                eni,
                dict,
            ):
                continue

            network_interface_id = (
                eni.get(
                    "NetworkInterfaceId"
                )
            )

            if network_interface_id:
                network_interfaces.append(
                    network_interface_id
                )

        security_groups = []

        for group in (
            instance.get(
                "SecurityGroups",
                [],
            )
            or []
        ):

            if not isinstance(
                group,
                dict,
            ):
                continue

            group_id = group.get(
                "GroupId"
            )

            if group_id:
                security_groups.append(
                    group_id
                )

        return {
            "instance_id":
                instance.get(
                    "InstanceId"
                ),

            "instance_type":
                instance.get(
                    "InstanceType"
                ),

            "state":
                state.get(
                    "Name"
                ),

            "availability_zone":
                placement.get(
                    "AvailabilityZone"
                ),

            "subnet_id":
                instance.get(
                    "SubnetId"
                ),

            "vpc_id":
                instance.get(
                    "VpcId"
                ),

            "private_ip":
                instance.get(
                    "PrivateIpAddress"
                ),

            "launch_time":
                self._isoformat(
                    instance.get(
                        "LaunchTime"
                    )
                ),

            "ami_id":
                instance.get(
                    "ImageId"
                ),

            "architecture":
                instance.get(
                    "Architecture"
                ),

            "platform":
                instance.get(
                    "Platform"
                ),

            "ebs_optimized":
                instance.get(
                    "EbsOptimized"
                ),

            "instance_lifecycle":
                instance.get(
                    "InstanceLifecycle"
                ),

            "root_device_name":
                instance.get(
                    "RootDeviceName"
                ),

            "root_device_type":
                instance.get(
                    "RootDeviceType"
                ),

            "block_devices":
                block_devices,

            "network_interface_ids":
                network_interfaces,

            "security_group_ids":
                security_groups,

            "tags":
                self._tags_to_dict(
                    instance.get(
                        "Tags",
                        [],
                    )
                ),

            "nodegroup":
                nodegroup.get(
                    "name"
                ),

            "autoscaling_group":
                asg_name,
        }

    # ==================================================================
    # FARGATE
    # ==================================================================

    def _collect_fargate_profiles(
        self,
        cluster_name: str,
    ) -> Tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: List[
            Dict[str, Any]
        ] = []

        errors: List[str] = []

        try:

            paginator = (
                self.eks.get_paginator(
                    "list_fargate_profiles"
                )
            )

            for page in paginator.paginate(
                clusterName=cluster_name
            ):

                for profile_name in page.get(
                    "fargateProfileNames",
                    [],
                ):

                    try:

                        response = (
                            self.eks
                            .describe_fargate_profile(
                                clusterName=cluster_name,
                                fargateProfileName=profile_name,
                            )
                        )

                        profile = (
                            response.get(
                                "fargateProfile",
                                {},
                            )
                        )

                        result.append(
                            {
                                "name":
                                    profile.get(
                                        "fargateProfileName"
                                    ),

                                "arn":
                                    profile.get(
                                        "fargateProfileArn"
                                    ),

                                "status":
                                    profile.get(
                                        "status"
                                    ),

                                "created_at":
                                    self._isoformat(
                                        profile.get(
                                            "createdAt"
                                        )
                                    ),

                                "pod_execution_role_arn":
                                    profile.get(
                                        "podExecutionRoleArn"
                                    ),

                                "subnets":
                                    list(
                                        profile.get(
                                            "subnets",
                                            [],
                                        )
                                        or []
                                    ),

                                "selectors":
                                    list(
                                        profile.get(
                                            "selectors",
                                            [],
                                        )
                                        or []
                                    ),

                                "tags":
                                    profile.get(
                                        "tags",
                                        {},
                                    ),
                            }
                        )

                    except Exception as exc:

                        errors.append(
                            (
                                "Failed to describe "
                                f"Fargate profile "
                                f"{profile_name}: "
                                f"{exc}"
                            )
                        )

        except Exception as exc:

            errors.append(
                (
                    "Failed to list Fargate "
                    f"profiles for {cluster_name}: "
                    f"{exc}"
                )
            )

        return result, errors

    # ==================================================================
    # ADDONS
    # ==================================================================

    def _collect_addons(
        self,
        cluster_name: Optional[str],
    ) -> List[Dict[str, Any]]:

        if not cluster_name:
            return []

        result: List[
            Dict[str, Any]
        ] = []

        try:

            paginator = (
                self.eks.get_paginator(
                    "list_addons"
                )
            )

            for page in paginator.paginate(
                clusterName=cluster_name
            ):

                for addon_name in page.get(
                    "addons",
                    [],
                ):

                    try:

                        response = (
                            self.eks.describe_addon(
                                clusterName=cluster_name,
                                addonName=addon_name,
                            )
                        )

                        addon = response.get(
                            "addon",
                            {},
                        )

                        result.append(
                            {
                                "name":
                                    addon.get(
                                        "addonName"
                                    ),

                                "version":
                                    addon.get(
                                        "addonVersion"
                                    ),

                                "status":
                                    addon.get(
                                        "status"
                                    ),

                                "created_at":
                                    self._isoformat(
                                        addon.get(
                                            "createdAt"
                                        )
                                    ),

                                "modified_at":
                                    self._isoformat(
                                        addon.get(
                                            "modifiedAt"
                                        )
                                    ),

                                "service_account_role_arn":
                                    addon.get(
                                        "serviceAccountRoleArn"
                                    ),

                                "owner":
                                    addon.get(
                                        "owner"
                                    ),

                                "publisher":
                                    addon.get(
                                        "publisher"
                                    ),

                                "configuration_values":
                                    addon.get(
                                        "configurationValues"
                                    ),

                                "health":
                                    addon.get(
                                        "health"
                                    ),
                            }
                        )

                    except Exception as exc:

                        print(
                            f"[EKS] Failed to describe "
                            f"addon {addon_name}: "
                            f"{exc}"
                        )

        except Exception as exc:

            print(
                f"[EKS] Failed to list addons "
                f"for {cluster_name}: {exc}"
            )

        return result

    # ==================================================================
    # OBSERVATIONS
    # ==================================================================

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cluster_name = resource.get(
            "name"
        )

        if not cluster_name:

            return {
                "cloudwatch": {
                    "status":
                        "incomplete",

                    "metrics": {},
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        namespace = self._namespace()

        cached = (
            self._metrics_batch_cache.get(
                cluster_name,
                {},
            )
        )

        cluster_series = (
            cached.get(
                "cluster",
                [],
            )
            if isinstance(
                cached,
                dict,
            )
            else []
        )

        node_series = (
            cached.get(
                "nodes",
                [],
            )
            if isinstance(
                cached,
                dict,
            )
            else []
        )

        pod_series = (
            cached.get(
                "pods",
                [],
            )
            if isinstance(
                cached,
                dict,
            )
            else []
        )

        cluster_group = (
            self._build_metric_group(
                cluster_series,
                group="cluster",
            )
        )

        node_group = (
            self._build_metric_group(
                node_series,
                group="nodes",
            )
        )

        pod_group = (
            self._build_metric_group(
                pod_series,
                group="pods",
            )
        )

        cloudwatch = {
            "status":
                "ok",

            "namespace":
                namespace,

            "cluster_name":
                cluster_name,

            "analysis_start":
                self._isoformat(
                    start
                ),

            "analysis_end":
                self._isoformat(
                    end
                ),

            "requested_period":
                self._requested_period(),

            "cluster":
                cluster_group,

            "nodes":
                node_group,

            "pods":
                pod_group,

            "data_quality":
                self._combine_metric_quality(
                    cluster_group,
                    node_group,
                    pod_group,
                ),
        }

        return {
            "cloudwatch":
                cloudwatch,

            "derived":
                self._build_derived_observations(
                    cluster_group,
                    node_group,
                    pod_group,
                ),
        }

    # ==================================================================
    # METRIC GROUP BUILDING
    # ==================================================================

    def _build_metric_group(
        self,
        series: List[Dict[str, Any]],
        *,
        group: str,
    ) -> Dict[str, Any]:

        metrics_by_name: Dict[
            str,
            List[Dict[str, Any]],
        ] = {}

        if not isinstance(
            series,
            list,
        ):
            series = []

        for metric in series:

            if not isinstance(
                metric,
                dict,
            ):
                continue

            metric_name = (
                metric.get(
                    "metric_name"
                )
                or metric.get(
                    "metric_key"
                )
            )

            if not metric_name:
                continue

            metrics_by_name.setdefault(
                str(metric_name),
                [],
            ).append(
                self._enrich_metric(
                    metric
                )
            )

        # Keep a compatibility aggregate under metrics[name].
        #
        # For node/pod groups this aggregate is calculated across
        # actual identified series. The individual series remain in
        # "series".
        aggregate_metrics: Dict[
            str,
            Dict[str, Any],
        ] = {}

        for name, entries in (
            metrics_by_name.items()
        ):

            aggregate_metrics[name] = (
                self._aggregate_series(
                    name,
                    entries,
                )
            )

        return {
            "status":
                "ok",

            "group":
                group,

            "metrics":
                aggregate_metrics,

            "series":
                {
                    name:
                        entries
                    for name, entries
                    in metrics_by_name.items()
                },

            "data_quality":
                {
                    "queried_metric_count":
                        len(series),

                    "observed_metric_count":
                        sum(
                            1
                            for metric
                            in series
                            if (
                                metric.get(
                                    "status"
                                )
                                == "ok"
                                and metric.get(
                                    "has_data"
                                )
                                is True
                            )
                        ),

                    "no_data_metric_count":
                        sum(
                            1
                            for metric
                            in series
                            if metric.get(
                                "status"
                            )
                            == "no_data"
                        ),

                    "metric_error_count":
                        sum(
                            1
                            for metric
                            in series
                            if metric.get(
                                "status"
                            )
                            == "error"
                        ),
                },
        }

    @classmethod
    def _enrich_metric(
        cls,
        metric: Dict[str, Any],
    ) -> Dict[str, Any]:

        result = dict(metric)

        raw_datapoints = result.get(
            "raw_datapoints",
            [],
        )

        if isinstance(
            raw_datapoints,
            list,
        ) and raw_datapoints:

            values = []

            for point in raw_datapoints:

                if not isinstance(
                    point,
                    dict,
                ):
                    continue

                value = point.get(
                    "value"
                )

                try:
                    if value is not None:
                        values.append(
                            float(value)
                        )
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

            if values:

                result["average"] = (
                    sum(values)
                    / len(values)
                )

                result["minimum"] = min(
                    values
                )

                result["maximum"] = max(
                    values
                )

                result["datapoint_count"] = (
                    len(values)
                )

        summary = result.get(
            "summary",
            {},
        )

        if not isinstance(
            summary,
            dict,
        ):
            summary = {}

        result["summary"] = {
            "average":
                cls._number(
                    summary.get(
                        "average",
                        result.get(
                            "average"
                        ),
                    )
                ),

            "minimum":
                cls._number(
                    summary.get(
                        "minimum",
                        result.get(
                            "minimum"
                        ),
                    )
                ),

            "maximum":
                cls._number(
                    summary.get(
                        "maximum",
                        result.get(
                            "maximum"
                        ),
                    )
                ),

            "datapoint_count":
                cls._number(
                    summary.get(
                        "datapoint_count",
                        result.get(
                            "datapoint_count"
                        ),
                    )
                ),

            "coverage_ratio":
                cls._number(
                    result.get(
                        "coverage_ratio"
                    )
                ),

            "coverage_percent":
                cls._number(
                    result.get(
                        "coverage_percent"
                    )
                ),
        }

        return result

    @classmethod
    def _aggregate_series(
        cls,
        metric_name: str,
        entries: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        observed = [
            item
            for item in entries
            if (
                item.get(
                    "status"
                )
                == "ok"
                and item.get(
                    "has_data"
                )
                is True
            )
        ]

        averages = [
            cls._number(
                item.get(
                    "summary",
                    {},
                ).get(
                    "average"
                )
            )
            for item in observed
        ]

        averages = [
            value
            for value in averages
            if value is not None
        ]

        maximums = [
            cls._number(
                item.get(
                    "summary",
                    {},
                ).get(
                    "maximum"
                )
            )
            for item in observed
        ]

        maximums = [
            value
            for value in maximums
            if value is not None
        ]

        minimums = [
            cls._number(
                item.get(
                    "summary",
                    {},
                ).get(
                    "minimum"
                )
            )
            for item in observed
        ]

        minimums = [
            value
            for value in minimums
            if value is not None
        ]

        coverage_values = [
            cls._number(
                item.get(
                    "coverage_percent"
                )
            )
            for item in observed
        ]

        coverage_values = [
            value
            for value in coverage_values
            if value is not None
        ]

        if not averages:

            return {
                "metric_name":
                    metric_name,

                "status":
                    "no_data",

                "has_data":
                    False,

                "series_count":
                    len(entries),

                "observed_series_count":
                    0,

                "average":
                    None,

                "minimum":
                    None,

                "maximum":
                    None,

                "coverage_percent":
                    (
                        min(coverage_values)
                        if coverage_values
                        else None
                    ),
            }

        # For an aggregate of resource series, an unweighted arithmetic
        # mean is deliberately used. It is presented as an operational
        # aggregate, not as billing usage.
        return {
            "metric_name":
                metric_name,

            "status":
                "ok",

            "has_data":
                True,

            "series_count":
                len(entries),

            "observed_series_count":
                len(observed),

            "average":
                (
                    sum(averages)
                    / len(averages)
                ),

            "minimum":
                (
                    min(minimums)
                    if minimums
                    else None
                ),

            "maximum":
                (
                    max(maximums)
                    if maximums
                    else None
                ),

            "coverage_percent":
                (
                    min(coverage_values)
                    if coverage_values
                    else None
                ),
        }

    # ==================================================================
    # DERIVED
    # ==================================================================

    def _build_derived_observations(
        self,
        cluster_group: Dict[str, Any],
        node_group: Dict[str, Any],
        pod_group: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "cluster": {
                "node_count":
                    self._metric_aggregate_value(
                        cluster_group,
                        "cluster_node_count",
                    ),

                "failed_node_count":
                    self._metric_aggregate_value(
                        cluster_group,
                        "cluster_failed_node_count",
                    ),
            },

            "nodes": {
                "series_count":
                    self._series_count(
                        node_group
                    ),

                "identified_node_count":
                    self._identified_node_count(
                        node_group
                    ),
            },

            "pods": {
                "series_count":
                    self._series_count(
                        pod_group
                    ),

                "identified_pod_count":
                    self._identified_pod_count(
                        pod_group
                    ),
            },

            "semantics": {
                "metric_aggregates_are_operational":
                    True,

                "missing_is_zero":
                    False,

                "node_series_identity":
                    list(
                        self.NODE_DIMENSIONS
                    ),

                "pod_series_identity":
                    list(
                        self.POD_DIMENSIONS
                    ),
            },
        }

    @staticmethod
    def _metric_aggregate_value(
        group: Dict[str, Any],
        metric_name: str,
    ) -> Any:

        metrics = group.get(
            "metrics",
            {},
        )

        if not isinstance(
            metrics,
            dict,
        ):
            return None

        metric = metrics.get(
            metric_name
        )

        if not isinstance(
            metric,
            dict,
        ):
            return None

        return metric.get(
            "average"
        )

    @staticmethod
    def _series_count(
        group: Dict[str, Any],
    ) -> int:

        series = group.get(
            "series",
            {},
        )

        if not isinstance(
            series,
            dict,
        ):
            return 0

        return sum(
            len(value)
            for value in series.values()
            if isinstance(
                value,
                list,
            )
        )

    @staticmethod
    def _identified_node_count(
        group: Dict[str, Any],
    ) -> int:

        series = group.get(
            "series",
            {},
        )

        if not isinstance(
            series,
            dict,
        ):
            return 0

        ids = set()

        for entries in series.values():

            if not isinstance(
                entries,
                list,
            ):
                continue

            for entry in entries:

                dimensions = (
                    entry.get(
                        "dimensions",
                        [],
                    )
                )

                if not isinstance(
                    dimensions,
                    list,
                ):
                    continue

                mapping = {
                    item.get(
                        "Name"
                    ):
                        item.get(
                            "Value"
                        )
                    for item in dimensions
                    if isinstance(
                        item,
                        dict,
                    )
                }

                value = mapping.get(
                    "InstanceId"
                )

                if value:
                    ids.add(
                        str(value)
                    )

        return len(ids)

    @staticmethod
    def _identified_pod_count(
        group: Dict[str, Any],
    ) -> int:

        series = group.get(
            "series",
            {},
        )

        if not isinstance(
            series,
            dict,
        ):
            return 0

        ids = set()

        for entries in series.values():

            if not isinstance(
                entries,
                list,
            ):
                continue

            for entry in entries:

                dimensions = (
                    entry.get(
                        "dimensions",
                        [],
                    )
                )

                if not isinstance(
                    dimensions,
                    list,
                ):
                    continue

                mapping = {
                    item.get(
                        "Name"
                    ):
                        item.get(
                            "Value"
                        )
                    for item in dimensions
                    if isinstance(
                        item,
                        dict,
                    )
                }

                cluster = mapping.get(
                    "ClusterName"
                )

                namespace = mapping.get(
                    "Namespace"
                )

                pod = mapping.get(
                    "PodName"
                )

                if (
                    cluster
                    and namespace
                    and pod
                ):
                    ids.add(
                        (
                            str(cluster),
                            str(namespace),
                            str(pod),
                        )
                    )

        return len(ids)

    # ==================================================================
    # OPTIMIZATION EVIDENCE
    # ==================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = self._dict(
            collected_resource.get(
                "configuration"
            )
        )

        compute = self._dict(
            configuration.get(
                "compute"
            )
        )

        observations = self._dict(
            collected_resource.get(
                "observations"
            )
        )

        cloudwatch = self._dict(
            observations.get(
                "cloudwatch"
            )
        )

        cluster_metrics = self._dict(
            cloudwatch.get(
                "cluster"
            )
        )

        node_metrics = self._dict(
            cloudwatch.get(
                "nodes"
            )
        )

        pod_metrics = self._dict(
            cloudwatch.get(
                "pods"
            )
        )

        summary = self._dict(
            compute.get(
                "summary"
            )
        )

        nodegroups = (
            compute.get(
                "nodegroups",
                [],
            )
        )

        fargate_profiles = (
            compute.get(
                "fargate_profiles",
                [],
            )
        )

        ec2_instances = (
            compute.get(
                "ec2_instances",
                [],
            )
        )

        if not isinstance(
            nodegroups,
            list,
        ):
            nodegroups = []

        if not isinstance(
            fargate_profiles,
            list,
        ):
            fargate_profiles = []

        if not isinstance(
            ec2_instances,
            list,
        ):
            ec2_instances = []

        return {
            "cost_model": {
                "control_plane_driver":
                    "eks_cluster_runtime",

                "worker_driver":
                    "ec2_instance_runtime",

                "fargate_driver":
                    "fargate_pod_runtime",

                "related_cost_drivers": [
                    "EBS",
                    "Elastic Load Balancing",
                    "NAT Gateway",
                    "Public IPv4",
                    "Data Transfer",
                ],
            },

            "cluster": {
                "cluster_id":
                    resource.get("id"),

                "cluster_name":
                    resource.get("name"),

                "status":
                    resource.get("status"),

                "version":
                    resource.get("version"),

                "created_at":
                    self._isoformat(
                        resource.get(
                            "createdAt"
                        )
                    ),

                "deletion_protection":
                    resource.get(
                        "deletionProtection"
                    ),
            },

            "capacity": {
                "inventory_status":
                    compute.get(
                        "inventory_status"
                    ),

                "inventory_errors":
                    compute.get(
                        "inventory_errors",
                        [],
                    ),

                "nodegroup_count":
                    len(nodegroups),

                "ec2_instance_count":
                    len(ec2_instances),

                "fargate_profile_count":
                    len(fargate_profiles),

                "desired_nodes":
                    summary.get(
                        "desired_node_count"
                    ),

                "minimum_nodes":
                    summary.get(
                        "minimum_node_count"
                    ),

                "maximum_nodes":
                    summary.get(
                        "maximum_node_count"
                    ),

                "nodegroups":
                    nodegroups,

                "ec2_instances":
                    ec2_instances,

                "fargate_profiles":
                    fargate_profiles,
            },

            "utilization": {
                "cluster":
                    self._metric_group_summary(
                        cluster_metrics
                    ),

                "nodes":
                    self._metric_group_summary(
                        node_metrics
                    ),

                "pods":
                    self._metric_group_summary(
                        pod_metrics
                    ),
            },

            "signals": {
                "cluster_active":
                    str(
                        resource.get(
                            "status"
                        )
                        or ""
                    ).upper()
                    == "ACTIVE",

                "has_managed_nodegroups":
                    bool(
                        nodegroups
                    ),

                "has_fargate":
                    bool(
                        fargate_profiles
                    ),

                "has_ec2_workers":
                    bool(
                        ec2_instances
                    ),
            },

            "relationships": {
                "vpc_id":
                    self._dict(
                        configuration.get(
                            "network"
                        )
                    ).get(
                        "vpc_id"
                    ),

                "subnet_ids":
                    list(
                        self._dict(
                            configuration.get(
                                "network"
                            )
                        ).get(
                            "subnet_ids",
                            [],
                        )
                        or []
                    ),

                "security_group_ids":
                    list(
                        self._dict(
                            configuration.get(
                                "network"
                            )
                        ).get(
                            "security_group_ids",
                            [],
                        )
                        or []
                    ),

                "ec2_instance_ids":
                    [
                        item.get(
                            "instance_id"
                        )
                        for item in ec2_instances
                        if isinstance(
                            item,
                            dict,
                        )
                        and item.get(
                            "instance_id"
                        )
                    ],

                "ebs_volume_ids":
                    sorted(
                        {
                            volume_id
                            for instance
                            in ec2_instances
                            if isinstance(
                                instance,
                                dict,
                            )
                            for volume
                            in instance.get(
                                "block_devices",
                                [],
                            )
                            if isinstance(
                                volume,
                                dict,
                            )
                            for volume_id in [
                                volume.get(
                                    "volume_id"
                                )
                            ]
                            if volume_id
                        }
                    ),

                "network_interface_ids":
                    sorted(
                        {
                            interface_id
                            for instance
                            in ec2_instances
                            if isinstance(
                                instance,
                                dict,
                            )
                            for interface_id
                            in instance.get(
                                "network_interface_ids",
                                [],
                            )
                            if interface_id
                        }
                    ),
            },

            "data_quality": {
                "cloudwatch_available":
                    bool(
                        cloudwatch
                    ),

                "cluster_metrics_available":
                    bool(
                        cluster_metrics.get(
                            "metrics"
                        )
                    ),

                "node_metrics_available":
                    bool(
                        node_metrics.get(
                            "metrics"
                        )
                    ),

                "pod_metrics_available":
                    bool(
                        pod_metrics.get(
                            "metrics"
                        )
                    ),

                "identified_node_count":
                    self._identified_node_count(
                        node_metrics
                    ),

                "identified_pod_count":
                    self._identified_pod_count(
                        pod_metrics
                    ),

                "collector":
                    collected_resource.get(
                        "data_quality",
                        {},
                    ),
            },
        }

    @classmethod
    def _metric_group_summary(
        cls,
        group: Any,
    ) -> Dict[str, Any]:

        if not isinstance(
            group,
            dict,
        ):
            return {
                "status":
                    "missing",

                "metrics":
                    {},

                "series":
                    {},
            }

        metrics = group.get(
            "metrics",
            {},
        )

        series = group.get(
            "series",
            {},
        )

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        if not isinstance(
            series,
            dict,
        ):
            series = {}

        return {
            "status":
                group.get(
                    "status"
                ),

            "metrics":
                {
                    str(key):
                        cls._metric_summary(
                            metrics.get(
                                key
                            )
                        )
                    for key in metrics
                },

            "series_count":
                sum(
                    len(value)
                    for value in series.values()
                    if isinstance(
                        value,
                        list,
                    )
                ),

            "data_quality":
                group.get(
                    "data_quality",
                    {},
                ),
        }

    @classmethod
    def _metric_summary(
        cls,
        metric: Any,
    ) -> Dict[str, Any]:

        if not isinstance(
            metric,
            dict,
        ):
            return {
                "status":
                    "missing",

                "has_data":
                    False,

                "average":
                    None,

                "minimum":
                    None,

                "maximum":
                    None,

                "coverage_percent":
                    None,
            }

        return {
            "status":
                metric.get(
                    "status"
                ),

            "has_data":
                metric.get(
                    "has_data"
                )
                is True,

            "series_count":
                cls._number(
                    metric.get(
                        "series_count"
                    )
                ),

            "observed_series_count":
                cls._number(
                    metric.get(
                        "observed_series_count"
                    )
                ),

            "average":
                cls._number(
                    metric.get(
                        "average"
                    )
                ),

            "minimum":
                cls._number(
                    metric.get(
                        "minimum"
                    )
                ),

            "maximum":
                cls._number(
                    metric.get(
                        "maximum"
                    )
                ),

            "coverage_percent":
                cls._number(
                    metric.get(
                        "coverage_percent"
                    )
                ),
        }

    # ==================================================================
    # RELATIONSHIPS
    # ==================================================================

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        vpc_config = (
            resource.get(
                "resourcesVpcConfig",
                {},
            )
            or {}
        )

        subnet_ids = list(
            vpc_config.get(
                "subnetIds",
                [],
            )
            or []
        )

        security_group_ids = list(
            vpc_config.get(
                "securityGroupIds",
                [],
            )
            or []
        )

        return {
            "status":
                "ok",

            "cluster": {
                "name":
                    resource.get(
                        "name"
                    ),

                "arn":
                    resource.get(
                        "arn"
                    ),
            },

            "vpc_id":
                vpc_config.get(
                    "vpcId"
                ),

            "subnets":
                subnet_ids,

            "security_groups":
                security_group_ids,

            "cluster_security_group":
                vpc_config.get(
                    "clusterSecurityGroupId"
                ),

            "summary": {
                "related_resource_count":
                    len(subnet_ids)
                    + len(
                        security_group_ids
                    ),
            },
        }

    # ==================================================================
    # TOPOLOGY
    # ==================================================================

    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        vpc_id = (
            resource.get(
                "resourcesVpcConfig",
                {},
            )
            or {}
        ).get(
            "vpcId"
        )

        if not vpc_id:

            return {
                "status":
                    "incomplete",

                "reason":
                    "EKS cluster has no VPC ID",
            }

        try:

            return (
                self.topology_collector.collect(
                    vpc_id=vpc_id,
                    resource_type=(
                        self.resource_type
                    ),
                    resource_id=(
                        self.get_resource_id(
                            resource
                        )
                    ),
                )
            )

        except Exception as exc:

            return {
                "status":
                    "error",

                "error":
                    str(exc),
            }

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _combine_metric_quality(
        *groups: Dict[str, Any],
    ) -> Dict[str, Any]:

        quality = {
            "queried_metric_count":
                0,

            "observed_metric_count":
                0,

            "no_data_metric_count":
                0,

            "metric_error_count":
                0,
        }

        for group in groups:

            if not isinstance(
                group,
                dict,
            ):
                continue

            data_quality = (
                group.get(
                    "data_quality",
                    {},
                )
            )

            if not isinstance(
                data_quality,
                dict,
            ):
                continue

            for key in quality:

                value = data_quality.get(
                    key,
                    0,
                )

                if isinstance(
                    value,
                    (int, float),
                ):
                    quality[key] += int(
                        value
                    )

        return quality

    @staticmethod
    def _number(
        value: Any,
    ) -> Optional[float]:

        if value is None:
            return None

        if isinstance(
            value,
            bool,
        ):
            return float(
                int(value)
            )

        try:
            return float(value)
        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _number_or_zero(
        cls,
        value: Any,
    ) -> int:

        parsed = cls._number(
            value
        )

        if parsed is None:
            return 0

        return int(parsed)

    @staticmethod
    def _dict(
        value: Any,
    ) -> Dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _tags_to_dict(
        tags: Any,
    ) -> Dict[str, str]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        result: Dict[
            str,
            str,
        ] = {}

        for tag in tags:

            if not isinstance(
                tag,
                dict,
            ):
                continue

            key = tag.get(
                "Key"
            )

            if key:

                result[
                    str(key)
                ] = str(
                    tag.get(
                        "Value",
                        "",
                    )
                )

        return result

    @staticmethod
    def _normalize_encryption(
        encryption_config: Any,
    ) -> List[Dict[str, Any]]:

        result: List[
            Dict[str, Any]
        ] = []

        if not isinstance(
            encryption_config,
            list,
        ):
            return result

        for item in encryption_config:

            if not isinstance(
                item,
                dict,
            ):
                continue

            provider = (
                item.get(
                    "provider",
                    {},
                )
                or {}
            )

            if not isinstance(
                provider,
                dict,
            ):
                provider = {}

            result.append(
                {
                    "resources":
                        item.get(
                            "resources",
                            [],
                        ),

                    "key_arn":
                        provider.get(
                            "keyArn"
                        ),
                }
            )

        return result

    @staticmethod
    def _normalize_datetime(
        value: Any,
    ) -> Optional[datetime]:

        if value is None:
            return None

        if isinstance(
            value,
            datetime,
        ):

            if value.tzinfo is None:
                return value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(
                timezone.utc
            )

        if isinstance(
            value,
            date,
        ):

            return datetime(
                value.year,
                value.month,
                value.day,
                tzinfo=timezone.utc,
            )

        if isinstance(
            value,
            str,
        ):

            text = value.strip()

            if not text:
                return None

            if text.endswith(
                "Z"
            ):
                text = (
                    text[:-1]
                    + "+00:00"
                )

            parsed = (
                datetime.fromisoformat(
                    text
                )
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(
                timezone.utc
            )

        raise TypeError(
            "Unsupported datetime value: "
            f"{type(value).__name__}"
        )

    @classmethod
    def _isoformat(
        cls,
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        normalized = (
            cls._normalize_datetime(
                value
            )
        )

        if normalized is not None:
            return normalized.isoformat()

        return str(value)