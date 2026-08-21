"""
AWS EBS volume collector.

Collects EBS volume inventory, attachment evidence, and CloudWatch
utilization metrics.

The collector does not calculate cost and does not assume that a
billing amount can be attributed to an individual EBS volume.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collection.base import BaseCollector
from collection.registry import register

from collection.metrics.cloudwatch import CloudWatchMetricCollector


@register
class EBSCollector(BaseCollector):

    key = "ebs"
    resource_type = "ebs_volume"

    DEFAULT_NAMESPACE = "AWS/EBS"
    DEFAULT_PERIOD = 3600

    def __init__(
        self,
        scan,
        region: Optional[str] = None,
        profile: Optional[dict] = None,
    ):
        super().__init__(
            scan=scan,
            region=region,
            profile=profile,
        )

        self.ec2 = get_client(
            "ec2",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.metric_collector = CloudWatchMetricCollector(
            self.cloudwatch
        )

        self._metrics_batch_cache: dict[
            str,
            List[Dict[str, Any]],
        ] = {}

    def _profile_section(
        self,
        name: str,
    ) -> dict[str, Any]:

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
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    def _cloudwatch_profile(
        self,
    ) -> dict[str, Any]:

        observations = self._profile_section(
            "observations"
        )

        return self._dict(
            observations.get(
                "cloudwatch"
            )
        )

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        paginator = self.ec2.get_paginator(
            "describe_volumes"
        )

        resources: List[Dict[str, Any]] = []

        for page in paginator.paginate():

            for volume in page.get(
                "Volumes",
                [],
            ):

                volume_id = volume.get(
                    "VolumeId"
                )

                if not volume_id:
                    continue

                resources.append(
                    {
                        "id": volume_id,
                        "raw": volume,
                    }
                )

        # CloudWatch is fetched once for all discovered volumes.
        self._prefetch_metrics_batch(
            resources
        )

        return resources

    # ------------------------------------------------------------------
    # CloudWatch batch collection
    # ------------------------------------------------------------------

    def _prefetch_metrics_batch(
        self,
        resources: List[Dict[str, Any]],
    ) -> None:

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if not cloudwatch_profile:
            return

        if cloudwatch_profile.get(
            "enabled",
            True,
        ) is False:
            return

        metric_specs = cloudwatch_profile.get(
            "metrics",
            [],
        )

        if not isinstance(
            metric_specs,
            list,
        ) or not metric_specs:
            return

        namespace = str(
            cloudwatch_profile.get(
                "namespace"
            )
            or self.DEFAULT_NAMESPACE
        ).strip()

        requested_period = int(
            cloudwatch_profile.get(
                "period",
                self.DEFAULT_PERIOD,
            )
        )

        try:
            start, end = (
                self.get_analysis_period()
            )
        except ValueError:
            return

        requests: List[Dict[str, Any]] = [
            {
                "resource_key": resource["id"],
                "namespace": namespace,
                "dimensions": [
                    {
                        "Name": "VolumeId",
                        "Value": resource["id"],
                    }
                ],
                "metric_specs": metric_specs,
            }
            for resource in resources
            if resource.get("id")
        ]

        if not requests:
            return

        self._metrics_batch_cache = (
            self.metric_collector.collect_batch(
                requests,
                start=start,
                end=end,
                requested_period=requested_period,
            )
        )

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return str(
            resource["id"]
        )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        volume = resource["raw"]

        tags = self._tags(
            volume.get(
                "Tags",
                [],
            )
        )

        return {
            "name":
                tags.get(
                    "Name"
                )
                or resource["id"],

            "volume_id":
                resource["id"],

            "state":
                volume.get(
                    "State"
                ),

            "tags":
                tags,
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        volume = resource["raw"]

        attachments = self._normalize_attachments(
            volume.get(
                "Attachments",
                [],
            )
        )

        return {
            "volume_id":
                resource["id"],

            "availability_zone":
                volume.get(
                    "AvailabilityZone"
                ),

            "state":
                volume.get(
                    "State"
                ),

            "size_gib":
                volume.get(
                    "Size"
                ),

            "volume_type":
                volume.get(
                    "VolumeType"
                ),

            "iops":
                volume.get(
                    "Iops"
                ),

            "throughput_mibps":
                volume.get(
                    "Throughput"
                ),

            "encrypted":
                volume.get(
                    "Encrypted"
                ),

            "kms_key_id":
                volume.get(
                    "KmsKeyId"
                ),

            "snapshot_id":
                volume.get(
                    "SnapshotId"
                ),

            "create_time":
                (
                    volume["CreateTime"].isoformat()
                    if volume.get("CreateTime")
                    else None
                ),

            "attachments":
                attachments,

            "attachment_count":
                len(attachments),

            "attached":
                bool(attachments),

            "instance_ids":
                sorted(
                    {
                        attachment.get(
                            "instance_id"
                        )
                        for attachment
                        in attachments
                        if attachment.get(
                            "instance_id"
                        )
                    }
                ),

            "tags":
                self._tags(
                    volume.get(
                        "Tags",
                        [],
                    )
                ),
        }

    @staticmethod
    def _normalize_attachments(
        raw_attachments: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:

        attachments: List[Dict[str, Any]] = []

        for attachment in raw_attachments or []:

            if not isinstance(
                attachment,
                dict,
            ):
                continue

            attachments.append(
                {
                    "instance_id":
                        attachment.get(
                            "InstanceId"
                        ),

                    "device":
                        attachment.get(
                            "Device"
                        ),

                    "state":
                        attachment.get(
                            "State"
                        ),

                    "delete_on_termination":
                        attachment.get(
                            "DeleteOnTermination"
                        ),
                }
            )

        return attachments

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        volume = resource["raw"]

        attachments = self._normalize_attachments(
            volume.get(
                "Attachments",
                [],
            )
        )

        return {
            "instance_ids":
                sorted(
                    {
                        attachment.get(
                            "instance_id"
                        )
                        for attachment
                        in attachments
                        if attachment.get(
                            "instance_id"
                        )
                    }
                ),

            "attachment_count":
                len(attachments),
        }

    # ------------------------------------------------------------------
    # Observations
    # ------------------------------------------------------------------

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        cloudwatch_profile = (
            self._cloudwatch_profile()
        )

        if not cloudwatch_profile:
            return {
                "status": "disabled",
                "cloudwatch": {},
            }

        enabled = cloudwatch_profile.get(
            "enabled",
            True,
        )

        if enabled is False:
            return {
                "status": "disabled",
                "cloudwatch": {},
            }

        namespace = str(
            cloudwatch_profile.get(
                "namespace"
            )
            or self.DEFAULT_NAMESPACE
        ).strip()

        requested_period = int(
            cloudwatch_profile.get(
                "period",
                self.DEFAULT_PERIOD,
            )
        )

        try:
            start, end = (
                self.get_analysis_period()
            )
        except ValueError:
            return {
                "status": "disabled",
                "cloudwatch": {},
            }

        results = (
            self._metrics_batch_cache.get(
                resource["id"],
                [],
            )
        )

        metrics: Dict[str, Any] = {}

        for result in results:

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:
                metrics[
                    metric_name
                ] = result

        return {
            "status": "ok",

            "cloudwatch": {
                "namespace":
                    namespace,

                "requested_period":
                    requested_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions": [
                    {
                        "Name": "VolumeId",
                        "Value": resource["id"],
                    }
                ],

                "metrics":
                    metrics,
            },
        }

    # ------------------------------------------------------------------
    # Optimization evidence
    # ------------------------------------------------------------------

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

        return {
            "resource": {
                "volume_id":
                    configuration.get(
                        "volume_id"
                    ),

                "volume_type":
                    configuration.get(
                        "volume_type"
                    ),

                "size_gib":
                    configuration.get(
                        "size_gib"
                    ),

                "attached":
                    configuration.get(
                        "attached"
                    ),

                "state":
                    configuration.get(
                        "state"
                    ),
            },

            "data_quality": {
                "cloudwatch_available":
                    bool(
                        cloudwatch.get(
                            "metrics",
                            {},
                        )
                    ),
            },
        }

    @staticmethod
    def _dict(
        value: Any,
    ) -> dict[str, Any]:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )

    @staticmethod
    def _tags(
        tags: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        if not isinstance(
            tags,
            list,
        ):
            return {}

        return {
            tag["Key"]:
                tag.get("Value")
            for tag in tags
            if isinstance(
                tag,
                dict,
            )
            and tag.get(
                "Key"
            )
        }
