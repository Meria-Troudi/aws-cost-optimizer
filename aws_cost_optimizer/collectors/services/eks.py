"""
Amazon EKS collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register
from collectors.network.topology import NetworkTopologyCollector


@register
class EksCollector(BaseCollector):

    key = "eks"
    resource_type = "eks_cluster"

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

        self._topology_collector = (
            NetworkTopologyCollector(
                self.region
            )
        )

    def discover(self) -> List[Dict[str, Any]]:

        clusters: List[Dict[str, Any]] = []

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

                    response = self.eks.describe_cluster(
                        name=cluster_name
                    )

                    cluster = response.get(
                        "cluster"
                    )

                    if cluster:
                        clusters.append(cluster)

                except Exception as exc:

                    print(
                        f"[EKS] Failed to describe "
                        f"cluster {cluster_name}: {exc}"
                    )

        return clusters

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return (
            resource.get("arn")
            or resource.get("name")
        )

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "name": resource.get("name"),
            "arn": resource.get("arn"),
            "cluster_id": resource.get("id"),
            "state": resource.get("status"),
            "version": resource.get("version"),
            "created_at": self._isoformat(
                resource.get("createdAt")
            ),
            "tags": resource.get(
                "tags",
                {},
            ),
        }

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        vpc_config = resource.get(
            "resourcesVpcConfig",
            {},
        )

        kubernetes_network = resource.get(
            "kubernetesNetworkConfig",
            {},
        )

        access_config = resource.get(
            "accessConfig",
            {},
        )

        compute = self._collect_compute(
            resource.get("name")
        )

        addons = self._collect_addons(
            resource.get("name")
        )

        return {
            "cluster": {
                "name": resource.get("name"),
                "arn": resource.get("arn"),
                "id": resource.get("id"),
                "platform_version": resource.get(
                    "platformVersion"
                ),
                "version": resource.get(
                    "version"
                ),
                "status": resource.get(
                    "status"
                ),
                "created_at": self._isoformat(
                    resource.get("createdAt")
                ),
                "endpoint": resource.get(
                    "endpoint"
                ),
                "role_arn": resource.get(
                    "roleArn"
                ),
                "certificate_authority": bool(
                    resource.get(
                        "certificateAuthority"
                    )
                ),
            },

            "network": {
                "vpc_id": vpc_config.get(
                    "vpcId"
                ),
                "subnet_ids": vpc_config.get(
                    "subnetIds",
                    [],
                ),
                "security_group_ids": vpc_config.get(
                    "securityGroupIds",
                    [],
                ),
                "endpoint_public_access": vpc_config.get(
                    "endpointPublicAccess"
                ),
                "endpoint_private_access": vpc_config.get(
                    "endpointPrivateAccess"
                ),
                "public_access_cidrs": vpc_config.get(
                    "publicAccessCidrs",
                    [],
                ),
                "cluster_security_group_id": vpc_config.get(
                    "clusterSecurityGroupId"
                ),
            },

            "kubernetes_network": {
                "ip_family": kubernetes_network.get(
                    "ipFamily"
                ),
                "service_ipv4_cidr": kubernetes_network.get(
                    "serviceIpv4Cidr"
                ),
                "service_ipv6_cidr": kubernetes_network.get(
                    "serviceIpv6Cidr"
                ),
            },

            "encryption": self._normalize_encryption(
                resource.get(
                    "encryptionConfig",
                    [],
                )
            ),

            "access": {
                "authentication_mode": access_config.get(
                    "authenticationMode"
                ),
                "bootstrap_cluster_creator_admin_permissions":
                    access_config.get(
                        "bootstrapClusterCreatorAdminPermissions"
                    ),
            },

            "logging": resource.get(
                "logging",
                {},
            ),

            "compute": compute,

            "addons": addons,
        }

    def _collect_compute(
        self,
        cluster_name: Optional[str],
    ) -> Dict[str, Any]:

        if not cluster_name:
            return {
                "nodegroups": [],
                "fargate_profiles": [],
                "summary": {
                    "nodegroup_count": 0,
                    "fargate_profile_count": 0,
                    "desired_node_count": 0,
                    "minimum_node_count": 0,
                    "maximum_node_count": 0,
                },
            }

        nodegroups = self._collect_nodegroups(
            cluster_name
        )

        fargate_profiles = (
            self._collect_fargate_profiles(
                cluster_name
            )
        )

        desired = 0
        minimum = 0
        maximum = 0

        for nodegroup in nodegroups:

            scaling = nodegroup.get(
                "scaling",
                {},
            )

            desired += (
                scaling.get(
                    "desired_size",
                    0,
                )
                or 0
            )

            minimum += (
                scaling.get(
                    "min_size",
                    0,
                )
                or 0
            )

            maximum += (
                scaling.get(
                    "max_size",
                    0,
                )
                or 0
            )

        return {
            "nodegroups": nodegroups,
            "fargate_profiles": fargate_profiles,

            "summary": {
                "nodegroup_count": len(
                    nodegroups
                ),
                "fargate_profile_count": len(
                    fargate_profiles
                ),
                "desired_node_count": desired,
                "minimum_node_count": minimum,
                "maximum_node_count": maximum,
            },
        }

    def _collect_nodegroups(
        self,
        cluster_name: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:

            paginator = self.eks.get_paginator(
                "list_nodegroups"
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

                        scaling = nodegroup.get(
                            "scalingConfig",
                            {},
                        )

                        update = nodegroup.get(
                            "updateConfig",
                            {},
                        )

                        resources = nodegroup.get(
                            "resources",
                            {},
                        )

                        result.append(
                            {
                                "name": nodegroup.get(
                                    "nodegroupName"
                                ),

                                "arn": nodegroup.get(
                                    "nodegroupArn"
                                ),

                                "status": nodegroup.get(
                                    "status"
                                ),

                                "created_at": self._isoformat(
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

                                "subnets":
                                    nodegroup.get(
                                        "subnets",
                                        [],
                                    ),

                                "node_role":
                                    nodegroup.get(
                                        "nodeRole"
                                    ),

                                "resources": {
                                    "auto_scaling_group_names":
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

                        print(
                            f"[EKS] Failed to describe "
                            f"nodegroup "
                            f"{nodegroup_name}: {exc}"
                        )

        except Exception as exc:

            print(
                f"[EKS] Failed to list nodegroups "
                f"for {cluster_name}: {exc}"
            )

        return result

    def _collect_fargate_profiles(
        self,
        cluster_name: str,
    ) -> List[Dict[str, Any]]:

        result: List[Dict[str, Any]] = []

        try:

            paginator = self.eks.get_paginator(
                "list_fargate_profiles"
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
                            self.eks.describe_fargate_profile(
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
                                "name": profile.get(
                                    "fargateProfileName"
                                ),

                                "arn": profile.get(
                                    "fargateProfileArn"
                                ),

                                "status": profile.get(
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

                        print(
                            f"[EKS] Failed to describe "
                            f"Fargate profile "
                            f"{profile_name}: {exc}"
                        )

        except Exception as exc:

            print(
                f"[EKS] Failed to list Fargate "
                f"profiles for {cluster_name}: {exc}"
            )
        return result

    def _collect_addons(
        self,
        cluster_name: Optional[str],
    ) -> List[Dict[str, Any]]:

        if not cluster_name:
            return []

        result: List[Dict[str, Any]] = []

        try:

            paginator = self.eks.get_paginator(
                "list_addons"
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
                            f"addon {addon_name}: {exc}"
                        )

        except Exception as exc:

            print(
                f"[EKS] Failed to list addons "
                f"for {cluster_name}: {exc}"
            )

        return result

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cluster_name = resource.get("name")

        if not cluster_name:
            return {
                "status": "incomplete",
                "summary": {
                    "related_resource_count": 0,
                },
            }


        vpc_config = resource.get(
            "resourcesVpcConfig",
            {},
        )

        return {
            "status": "ok",

            "cluster": {
                "cluster_name": cluster_name,
                "cluster_arn": resource.get(
                    "arn"
                ),
            },

            "vpc_id": vpc_config.get(
                "vpcId"
            ),

            "subnets": vpc_config.get(
                "subnetIds",
                [],
            ),

            "security_groups": vpc_config.get(
                "securityGroupIds",
                [],
            ),

            "summary": {
                "related_resource_count": 0,
            },
        }


    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        vpc_config = resource.get(
            "resourcesVpcConfig",
            {},
        )

        vpc_id = vpc_config.get(
            "vpcId"
        )

        if not vpc_id:

            return {
                "status": "incomplete",
                "reason": "EKS cluster has no VPC ID",
            }

        return self._topology_collector.collect(
            vpc_id=vpc_id,
            resource_type=self.resource_type,
            resource_id=self.get_resource_id(
                resource
            ),
        )

    def build_optimization_evidence(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        configuration = collected_resource.get(
            "configuration",
            {},
        )

        compute = configuration.get(
            "compute",
            {},
        )

        summary = compute.get(
            "summary",
            {},
        )

        nodegroups = compute.get(
            "nodegroups",
            [],
        )

        fargate_profiles = compute.get(
            "fargate_profiles",
            [],
        )

        desired_nodes = (
            summary.get(
                "desired_node_count",
                0,
            )
            or 0
        )

        minimum_nodes = (
            summary.get(
                "minimum_node_count",
                0,
            )
            or 0
        )

        return {
            "cost_model": {
                "billing_metric":
                    "AmazonEKS-Hours:perCluster",

                "cost_driver":
                    "cluster_count_and_cluster_runtime",
            },

            "cluster": {
                "status":
                    resource.get("status"),

                "created_at":
                    self._isoformat(
                        resource.get("createdAt")
                    ),

                "version":
                    resource.get("version"),
            },

            "compute": {
                "nodegroup_count":
                    len(nodegroups),

                "fargate_profile_count":
                    len(fargate_profiles),

                "desired_node_count":
                    desired_nodes,

                "minimum_node_count":
                    minimum_nodes,
            },

            "signals": {
                "cluster_active":
                    resource.get("status") == "ACTIVE",

                "has_nodegroups":
                    bool(nodegroups),

                "has_fargate_profiles":
                    bool(fargate_profiles),

                "has_desired_nodes":
                    desired_nodes > 0,

                "all_nodegroups_at_zero":
                    bool(nodegroups)
                    and desired_nodes == 0,

                "no_compute_attached":
                    not nodegroups
                    and not fargate_profiles,
            },
        }

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

        for item in encryption_config:

            if not isinstance(
                item,
                dict,
            ):
                continue

            provider = item.get(
                "provider",
                {},
            )

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
    def _isoformat(
        value: Any,
    ) -> Optional[str]:

        if value is None:
            return None

        if isinstance(
            value,
            datetime,
        ):

            if value.tzinfo is None:
                value = value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(
                timezone.utc
            ).isoformat()

        return str(value)