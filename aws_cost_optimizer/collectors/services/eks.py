"""
Amazon EKS collector.

Collects:
- EKS cluster identity/configuration
- managed nodegroups
- managed node EC2 inventory
- Fargate profiles
- addons
- Container Insights observations
- network topology
- relationships
- lifecycle events

The collector exposes evidence only.

It does not make optimization decisions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from collectors.network.topology import (
    NetworkTopologyCollector,
)

from collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)


@register
class EksCollector(BaseCollector):

    key = "eks"
    resource_type = "eks_cluster"

    CLOUDWATCH_METRICS = [
        {
            "name":
                "node_cpu_utilization",

            "statistic":
                "Average",

            "unit":
                "Percent",

            "key":
                "node_cpu_utilization",
        },
        {
            "name":
                "node_memory_utilization",

            "statistic":
                "Average",

            "unit":
                "Percent",

            "key":
                "node_memory_utilization",
        },
        {
            "name":
                "node_cpu_reserved_capacity",

            "statistic":
                "Average",

            "unit":
                "Percent",

            "key":
                "node_cpu_reserved_capacity",
        },
        {
            "name":
                "node_memory_reserved_capacity",

            "statistic":
                "Average",

            "unit":
                "Percent",

            "key":
                "node_memory_reserved_capacity",
        },
        {
            "name":
                "node_number_of_running_pods",

            "statistic":
                "Average",

            "unit":
                "Count",

            "key":
                "running_pods",
        },
        {
            "name":
                "cluster_node_count",

            "statistic":
                "Average",

            "unit":
                "Count",

            "key":
                "cluster_node_count",
        },
        {
            "name":
                "cluster_failed_node_count",

            "statistic":
                "Average",

            "unit":
                "Count",

            "key":
                "failed_node_count",
        },
        {
            "name":
                "node_network_total_bytes",

            "statistic":
                "Average",

            "unit":
                "Bytes/Second",

            "key":
                "node_network_total_bytes",
        },
    ]

    def __init__(
        self,
        scan,
        region=None,
        profile=None,
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

        self.cloudtrail = get_client(
            "cloudtrail",
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

    # ==================================================================
    # DISCOVERY
    # ==================================================================

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        clusters: list[
            Dict[str, Any]
        ] = []

        paginator = (
            self.eks.get_paginator(
                "list_clusters"
            )
        )

        for page in paginator.paginate():

            for cluster_name in page.get(
                "clusters",
                [],
            ):

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

        return clusters

    # ==================================================================
    # IDENTITY
    # ==================================================================

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        value = (
            resource.get("arn")
            or resource.get("name")
        )

        if not value:

            raise ValueError(
                "EKS cluster has no ARN or name"
            )

        return str(
            value
        )

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
                    resource.get("createdAt")
                ),

            "tags":
                resource.get(
                    "tags",
                    {},
                ),
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
                        resource.get("createdAt")
                    ),

                "endpoint":
                    resource.get("endpoint"),

                "role_arn":
                    resource.get("roleArn"),

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
                    vpc_config.get(
                        "vpcId"
                    ),

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

        errors: list[str] = []

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

            desired += (
                self._number_or_zero(
                    scaling.get(
                        "desired_size"
                    )
                )
            )

            minimum += (
                self._number_or_zero(
                    scaling.get(
                        "min_size"
                    )
                )
            )

            maximum += (
                self._number_or_zero(
                    scaling.get(
                        "max_size"
                    )
                )
            )

        # "fargate_running" cannot be inferred from the existence
        # of a Fargate profile. Leave it unknown unless another
        # collector supplies explicit workload evidence.
        fargate_running = None

        return {
            "inventory_status":
                (
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

            "fargate_running":
                fargate_running,

            "summary": {
                "nodegroup_count":
                    len(nodegroups),

                "fargate_profile_count":
                    len(fargate_profiles),

                "ec2_instance_count":
                    len(ec2_instances),

                "desired_node_count":
                    desired,

                "minimum_node_count":
                    minimum,

                "maximum_node_count":
                    maximum,
            },
        }

    # ==================================================================
    # NODEGROUPS
    # ==================================================================

    def _collect_nodegroups(
        self,
        cluster_name: str,
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: list[
            Dict[str, Any]
        ] = []

        errors: list[str] = []

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

                                "instance_types":
                                    nodegroup.get(
                                        "instanceTypes",
                                        [],
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
                                    nodegroup.get(
                                        "subnets",
                                        [],
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

        return (
            result,
            errors,
        )

    # ==================================================================
    # EC2 WORKERS
    # ==================================================================

    def _collect_ec2_instances(
        self,
        nodegroups: List[Dict[str, Any]],
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: list[
            Dict[str, Any]
        ] = []

        errors: list[str] = []

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
                            f"Failed to inspect ASG "
                            f"{asg_name}: {exc}"
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

                        instance_id = (
                            instance.get(
                                "InstanceId"
                            )
                        )

                        if not instance_id:
                            continue

                        if instance_id in seen_instance_ids:
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
                                    f"Failed to describe "
                                    f"EC2 instance "
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

        return (
            result,
            errors,
        )

    @staticmethod
    def _instance_record(
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
                EksCollector._isoformat(
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

            "tags":
                EksCollector._tags_to_dict(
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
    ) -> tuple[
        List[Dict[str, Any]],
        List[str],
    ]:

        result: list[
            Dict[str, Any]
        ] = []

        errors: list[str] = []

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

                        profile = response.get(
                            "fargateProfile",
                            {},
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
                                    profile.get(
                                        "subnets",
                                        [],
                                    ),

                                "selectors":
                                    profile.get(
                                        "selectors",
                                        [],
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

        return (
            result,
            errors,
        )

    # ==================================================================
    # ADDONS
    # ==================================================================

    def _collect_addons(
        self,
        cluster_name: Optional[str],
    ) -> List[Dict[str, Any]]:

        if not cluster_name:
            return []

        result = []

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

                    "metrics":
                        {},
                }
            }

        start, end = (
            self.get_analysis_period()
        )

        try:

            metrics = (
                self.metric_collector.collect(
                    namespace="ContainerInsights",

                    dimensions=[
                        {
                            "Name":
                                "ClusterName",

                            "Value":
                                cluster_name,
                        }
                    ],

                    metric_specs=(
                        self.CLOUDWATCH_METRICS
                    ),

                    start=start,

                    end=end,

                    requested_period=3600,
                )
            )

        except Exception as exc:

            return {
                "cloudwatch": {
                    "status":
                        "error",

                    "namespace":
                        "ContainerInsights",

                    "metrics":
                        {},

                    "error":
                        str(exc),
                }
            }

        metric_map: dict[
            str,
            Dict[str, Any],
        ] = {}

        for metric in metrics:

            if not isinstance(
                metric,
                dict,
            ):
                continue

            metric_name = metric.get(
                "metric_name"
            )

            metric_key = metric.get(
                "metric_key"
            )

            # Preserve BOTH names. This prevents the
            # running_pods / failed_node_count alias problem.
            if metric_name:
                metric_map[
                    str(metric_name)
                ] = metric

            if metric_key:
                metric_map[
                    str(metric_key)
                ] = metric

        queried = sum(
            1
            for metric in self.CLOUDWATCH_METRICS
            if (
                metric.get(
                    "name"
                )
            )
        )

        observed = sum(
            1
            for metric in self.CLOUDWATCH_METRICS
            if self._metric_observed_by_key(
                metric_map,
                metric.get("key"),
                metric.get("name"),
            )
        )

        no_data = sum(
            1
            for metric in self.CLOUDWATCH_METRICS
            if self._metric_status_by_key(
                metric_map,
                metric.get("key"),
                metric.get("name"),
            )
            == "no_data"
        )

        errors = sum(
            1
            for metric in self.CLOUDWATCH_METRICS
            if self._metric_status_by_key(
                metric_map,
                metric.get("key"),
                metric.get("name"),
            )
            == "error"
        )

        effective_period = next(
            (
                metric.get(
                    "effective_period"
                )
                for metric in metric_map.values()
                if metric.get(
                    "effective_period"
                ) is not None
            ),
            3600,
        )

        return {
            "cloudwatch": {
                "status":
                    (
                        "error"
                        if errors == queried
                        and queried > 0
                        else "ok"
                    ),

                "namespace":
                    "ContainerInsights",

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
                    3600,

                "effective_period":
                    effective_period,

                "metrics":
                    metric_map,

                "data_quality": {
                    "queried_metric_count":
                        queried,

                    "observed_metric_count":
                        observed,

                    "no_data_metric_count":
                        no_data,

                    "metric_error_count":
                        errors,
                },
            }
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
                    resource_type=self.resource_type,
                    resource_id=self.get_resource_id(
                        resource
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
    # LIFECYCLE EVENTS
    # ==================================================================

    def collect_lifecycle_events(
        self,
        resource: Dict[str, Any],
        start=None,
        end=None,
    ) -> Dict[str, Any]:

        cluster_name = resource.get(
            "name"
        )

        if not cluster_name:

            return {
                "status":
                    "incomplete",

                "events":
                    [],
            }

        event_names = [
            "CreateCluster",
            "UpdateClusterConfig",
            "UpdateClusterVersion",
            "DeleteCluster",
        ]

        events = []

        for event_name in event_names:

            kwargs = {
                "LookupAttributes": [
                    {
                        "AttributeKey":
                            "EventName",

                        "AttributeValue":
                            event_name,
                    }
                ],

                "MaxResults":
                    50,
            }

            if start:

                kwargs[
                    "StartTime"
                ] = self._normalize_datetime(
                    start
                )

            if end:

                kwargs[
                    "EndTime"
                ] = self._normalize_datetime(
                    end
                )

            try:

                paginator = (
                    self.cloudtrail
                    .get_paginator(
                        "lookup_events"
                    )
                )

                for page in paginator.paginate(
                    **kwargs
                ):

                    for event in page.get(
                        "Events",
                        [],
                    ):

                        resources = (
                            event.get(
                                "Resources",
                                []
                            )
                        )

                        matches = any(
                            isinstance(
                                resource_item,
                                dict,
                            )
                            and resource_item.get(
                                "ResourceName"
                            )
                            == cluster_name
                            for resource_item
                            in resources
                        )

                        if not matches:
                            continue

                        events.append(
                            {
                                "event_id":
                                    event.get(
                                        "EventId"
                                    ),

                                "event_name":
                                    event.get(
                                        "EventName"
                                    ),

                                "event_time":
                                    self._isoformat(
                                        event.get(
                                            "EventTime"
                                        )
                                    ),

                                "username":
                                    event.get(
                                        "Username"
                                    ),

                                "event_source":
                                    event.get(
                                        "EventSource"
                                    ),

                                "read_only":
                                    event.get(
                                        "ReadOnly"
                                    ),

                                "resources":
                                    resources,
                            }
                        )

            except Exception as exc:

                print(
                    f"[EKS] CloudTrail lookup "
                    f"{event_name} failed: "
                    f"{exc}"
                )

        events.sort(
            key=lambda item:
                item.get(
                    "event_time"
                )
                or ""
        )

        return {
            "status":
                "ok",

            "cluster_name":
                cluster_name,

            "events":
                events,

            "event_count":
                len(events),
        }

    # ==================================================================
    # OPTIMIZATION EVIDENCE
    # ==================================================================

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = (
            collected_resource.get(
                "configuration",
                {},
            )
        )

        if not isinstance(
            configuration,
            dict,
        ):
            configuration = {}

        compute = (
            configuration.get(
                "compute",
                {},
            )
        )

        if not isinstance(
            compute,
            dict,
        ):
            compute = {}

        summary = (
            compute.get(
                "summary",
                {},
            )
        )

        if not isinstance(
            summary,
            dict,
        ):
            summary = {}

        nodegroups = compute.get(
            "nodegroups",
            [],
        )

        fargate_profiles = compute.get(
            "fargate_profiles",
            [],
        )

        ec2_instances = compute.get(
            "ec2_instances",
            [],
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

        observations = (
            collected_resource.get(
                "observations",
                {},
            )
        )

        if not isinstance(
            observations,
            dict,
        ):
            observations = {}

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch,
            dict,
        ):
            cloudwatch = {}

        metrics = cloudwatch.get(
            "metrics",
            {},
        )

        if not isinstance(
            metrics,
            dict,
        ):
            metrics = {}

        node_cpu = self._metric_value(
            metrics,
            "node_cpu_utilization",
        )

        node_memory = self._metric_value(
            metrics,
            "node_memory_utilization",
        )

        node_count = self._metric_value(
            metrics,
            "cluster_node_count",
        )

        running_pods = self._metric_value(
            metrics,
            "running_pods"
        )

        return {
            "cost_model": {
                "control_plane_driver":
                    "cluster_runtime",

                "worker_driver":
                    "ec2_instance_runtime",

                "fargate_driver":
                    "pod_runtime",

                "additional_cost_drivers": [
                    "EBS",
                    "LoadBalancer",
                    "NATGateway",
                    "PublicIPv4",
                    "DataTransfer",
                ],
            },

            "cluster": {
                "status":
                    resource.get(
                        "status"
                    ),

                "created_at":
                    self._isoformat(
                        resource.get(
                            "createdAt"
                        )
                    ),

                "version":
                    resource.get(
                        "version"
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
                    len(
                        nodegroups
                    ),

                "ec2_instance_count":
                    len(
                        ec2_instances
                    ),

                "fargate_profile_count":
                    len(
                        fargate_profiles
                    ),

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

                "fargate_running":
                    compute.get(
                        "fargate_running"
                    ),
            },

            "utilization": {
                "node_cpu_average":
                    node_cpu,

                "node_memory_average":
                    node_memory,

                "cluster_node_count":
                    node_count,

                "running_pods":
                    running_pods,
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

                "has_nodegroups":
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

                "all_nodegroups_at_zero":
                    bool(
                        nodegroups
                    )
                    and (
                        self._number(
                            summary.get(
                                "desired_node_count"
                            )
                        )
                        == 0
                    ),

                "no_compute_attached":
                    not nodegroups
                    and not fargate_profiles,

                "low_cpu_utilization":
                    (
                        node_cpu is not None
                        and node_cpu
                        < 20
                    ),

                "low_memory_utilization":
                    (
                        node_memory is not None
                        and node_memory
                        < 30
                    ),

                "large_capacity_buffer":
                    self._large_capacity_buffer(
                        nodegroups
                    ),
            },
        }

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _metric_status_by_key(
        metric_map: Dict[str, Any],
        key: Optional[str],
        metric_name: Optional[str],
    ) -> Optional[str]:

        metric = (
            metric_map.get(
                key
            )
            if key
            else None
        )

        if metric is None and metric_name:
            metric = metric_map.get(
                metric_name
            )

        if not isinstance(
            metric,
            dict,
        ):
            return None

        return metric.get(
            "status"
        )

    @staticmethod
    def _metric_observed_by_key(
        metric_map: Dict[str, Any],
        key: Optional[str],
        metric_name: Optional[str],
    ) -> bool:

        metric = (
            metric_map.get(
                key
            )
            if key
            else None
        )

        if metric is None and metric_name:
            metric = metric_map.get(
                metric_name
            )

        return bool(
            isinstance(
                metric,
                dict,
            )
            and metric.get(
                "status"
            ) == "ok"
            and metric.get(
                "has_data"
            ) is True
        )

    @staticmethod
    def _metric_value(
        metric_map: Dict[str, Any],
        key: str,
    ) -> Optional[float]:

        metric = metric_map.get(
            key
        )

        if not isinstance(
            metric,
            dict,
        ):

            aliases = {
                "running_pods":
                    "node_number_of_running_pods",

                "failed_node_count":
                    "cluster_failed_node_count",

                "node_network_total_bytes":
                    "node_network_total_bytes",
            }

            alias = aliases.get(
                key
            )

            if alias:
                metric = metric_map.get(
                    alias
                )

        if not isinstance(
            metric,
            dict,
        ):
            return None

        if (
            metric.get(
                "status"
            )
            != "ok"
            or metric.get(
                "has_data"
            )
            is not True
        ):
            return None

        statistic = str(
            metric.get(
                "statistic",
                "",
            )
        ).lower()

        expected = {
            "node_cpu_utilization":
                "average",

            "node_memory_utilization":
                "average",

            "node_cpu_reserved_capacity":
                "average",

            "node_memory_reserved_capacity":
                "average",

            "running_pods":
                "average",

            "cluster_node_count":
                "average",

            "failed_node_count":
                "average",

            "node_network_total_bytes":
                "average",
        }.get(
            key
        )

        if (
            expected
            and statistic
            and statistic != expected
        ):
            return None

        for field in (
            "average",
            "value",
            "maximum",
        ):

            value = metric.get(
                field
            )

            if isinstance(
                value,
                (int, float),
            ):

                return float(
                    value
                )

        return None

    @staticmethod
    def _large_capacity_buffer(
        nodegroups: list[dict[str, Any]],
    ) -> bool:

        for nodegroup in nodegroups:

            if not isinstance(
                nodegroup,
                dict,
            ):
                continue

            scaling = nodegroup.get(
                "scaling",
                {},
            )

            if not isinstance(
                scaling,
                dict,
            ):
                continue

            desired = EksCollector._number(
                scaling.get(
                    "desired_size"
                )
            )

            maximum = EksCollector._number(
                scaling.get(
                    "max_size"
                )
            )

            if (
                desired is not None
                and maximum is not None
                and (
                    desired > 0
                    and maximum
                    > desired * 2
                    or
                    desired == 0
                    and maximum > 0
                )
            ):
                return True

        return False

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

            return float(
                value
            )

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

        return int(
            parsed
        )

    @staticmethod
    def _tags_to_dict(
        tags: List[Dict[str, Any]],
    ) -> Dict[str, str]:

        result: Dict[
            str,
            str,
        ] = {}

        for tag in (
            tags or []
        ):

            if not isinstance(
                tag,
                dict,
            ):
                continue

            key = tag.get(
                "Key"
            )

            value = tag.get(
                "Value"
            )

            if key:
                result[
                    str(key)
                ] = value

        return result

    @staticmethod
    def _normalize_encryption(
        encryption_config: Any,
    ) -> List[Dict[str, Any]]:

        result = []

        if not isinstance(
            encryption_config,
            list,
        ):
            return result

        for item in (
            encryption_config
        ):

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
        value,
    ):

        from datetime import timezone

        if value is None:
            return None

        if value.tzinfo is None:

            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )

    @classmethod
    def _isoformat(
        cls,
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        if hasattr(
            value,
            "isoformat",
        ):

            return cls._normalize_datetime(
                value
            ).isoformat()

        return str(
            value
        )