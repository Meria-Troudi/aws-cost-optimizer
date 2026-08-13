"""
RDS Collector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aws_cost_optimizer.config.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register

from aws_cost_optimizer.collectors.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)

from aws_cost_optimizer.collectors.network.topology import (
    NetworkTopologyCollector,
)


@register
class RDSCollector(BaseCollector):

    key = "rds"
    resource_type = "rds_instance"

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

        self.rds = get_client(
            "rds",
            self.region,
        )

        self.cloudwatch = get_client(
            "cloudwatch",
            self.region,
        )

        self.cloudtrail = get_client(
            "cloudtrail",
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

 
    def _profile_section(
        self,
        section: str,
    ) -> Dict[str, Any]:

        if not self.profile:
            return {}

        value = self.profile.get(
            section,
            {},
        )

        if not isinstance(
            value,
            dict,
        ):
            return {}

        return value

    @staticmethod
    def _enabled(
        section: Dict[str, Any],
        default: bool = False,
    ) -> bool:

        return (
            section.get(
                "enabled",
                default,
            )
            is True
        )

 
    def discover(
        self,
    ) -> List[Dict[str, Any]]:

        resources: List[
            Dict[str, Any]
        ] = []

        paginator = (
            self.rds.get_paginator(
                "describe_db_instances"
            )
        )

        for page in paginator.paginate():

            for db in page.get(
                "DBInstances",
                [],
            ):

                identifier = db.get(
                    "DBInstanceIdentifier"
                )

                if not identifier:
                    continue

                resources.append(
                    {
                        "id": identifier,
                        "raw": db,
                    }
                )

        return resources

    def get_resource_id(
        self,
        resource: Dict[str, Any],
    ) -> str:

        return resource["id"]

 
    @staticmethod
    def _field_definition(
        field: Any,
    ) -> tuple[str, str]:

        if isinstance(
            field,
            str,
        ):
            return (
                field,
                field,
            )

        if isinstance(
            field,
            dict,
        ):

            source = field.get(
                "source"
            )

            if not source:
                raise ValueError(
                    "Collection profile field is missing "
                    f"'source': {field!r}"
                )

            output = field.get(
                "output",
                source,
            )

            return (
                source,
                output,
            )

        raise ValueError(
            "Invalid collection profile field: "
            f"{field!r}"
        )

    @staticmethod
    def _get_nested(
        data: Dict[str, Any],
        path: str,
    ) -> Any:

        current: Any = data

        for part in path.split("."):

            if not isinstance(
                current,
                dict,
            ):
                return None

            current = current.get(
                part
            )

            if current is None:
                return None

        return current

    def _collect_fields(
        self,
        source: Dict[str, Any],
        section_name: str,
    ) -> Dict[str, Any]:

        section = (
            self._profile_section(
                section_name
            )
        )

        if not self._enabled(
            section
        ):
            return {}

        fields = section.get(
            "fields",
            [],
        )

        if not isinstance(
            fields,
            list,
        ):
            raise ValueError(
                f"'{section_name}.fields' "
                "must be a list"
            )

        result: Dict[str, Any] = {}

        for field in fields:

            source_path, output_name = (
                self._field_definition(
                    field
                )
            )

            result[output_name] = (
                self._get_nested(
                    source,
                    source_path,
                )
            )

        return result

    def collect_identity(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        return self._collect_fields(
            resource["raw"],
            "identity",
        )

    def collect_configuration(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        sections = (
            "configuration",
            "storage",
            "availability",
            "backup",
            "performance",
        )

        result: Dict[str, Any] = {}

        for section in sections:

            result.update(
                self._collect_fields(
                    resource["raw"],
                    section,
                )
            )

        return result

    def collect_relationships(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        section = (
            self._profile_section(
                "relationships"
            )
        )

        if not self._enabled(
            section
        ):
            return {}

        fields = section.get(
            "fields",
            [],
        )

        if not isinstance(
            fields,
            list,
        ):
            raise ValueError(
                "'relationships.fields' "
                "must be a list"
            )

        result: Dict[str, Any] = {}

        for field in fields:

            source_path, output_name = (
                self._field_definition(
                    field
                )
            )

            result[output_name] = (
                self._get_nested(
                    resource["raw"],
                    source_path,
                )
            )

        return result


    def collect_topology(
        self,
        resource: Dict[str, Any],
        collected_resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        topology_profile = (
            self._profile_section(
                "topology"
            )
        )

        network_profile = (
            self._profile_section(
                "network"
            )
        )

        enabled = topology_profile.get(
            "enabled",
            network_profile.get(
                "enabled",
                False,
            ),
        )

        if enabled is not True:
            return {}

        vpc_id = self._get_nested(
            resource["raw"],
            "DBSubnetGroup.VpcId",
        )

        if not vpc_id:

            return {
                "status":
                    "incomplete",

                "reason":
                    "RDS instance has no VPC ID",
            }

        return self.topology_collector.collect(
            vpc_id=vpc_id,
            resource_type=self.resource_type,
            resource_id=self.get_resource_id(
                resource
            ),
        )

    def collect_observations(
        self,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:

        observations = (
            self._profile_section(
                "observations"
            )
        )

        cloudwatch_profile = (
            observations.get(
                "cloudwatch",
                {},
            )
        )

        if not isinstance(
            cloudwatch_profile,
            dict,
        ):
            return {}

        if not self._enabled(
            cloudwatch_profile,
            default=True,
        ):
            return {}

        namespace = (
            cloudwatch_profile.get(
                "namespace"
            )
        )

        metrics = (
            cloudwatch_profile.get(
                "metrics",
                [],
            )
        )

        period = (
            cloudwatch_profile.get(
                "period"
            )
        )

        if not namespace:
            raise ValueError(
                "CloudWatch profile is missing "
                "'namespace'"
            )

        if not metrics:
            return {}

        if period is None:
            raise ValueError(
                "CloudWatch profile is missing "
                "'period'"
            )

        identifier = (
            resource["raw"].get(
                "DBInstanceIdentifier"
            )
        )

        if not identifier:
            return {}

        start, end = (
            self.get_analysis_period()
        )

        dimensions = [
            {
                "Name":
                    "DBInstanceIdentifier",

                "Value":
                    identifier,
            }
        ]

        results = (
            self.metric_collector.collect(
                namespace=namespace,
                dimensions=dimensions,
                metric_specs=metrics,
                start=start,
                end=end,
                requested_period=int(
                    period
                ),
            )
        )

        metric_results: Dict[
            str,
            Any,
        ] = {}

        for result in results:

            metric_name = result.get(
                "metric_name"
            )

            if metric_name:
                metric_results[
                    metric_name
                ] = result

        effective_period = (
            results[0].get(
                "effective_period",
                period,
            )
            if results
            else period
        )

        result = {
            "cloudwatch": {
                "namespace":
                    namespace,

                "requested_period":
                    period,

                "effective_period":
                    effective_period,

                "start":
                    start.isoformat(),

                "end":
                    end.isoformat(),

                "dimensions":
                    dimensions,

                "metrics":
                    metric_results,
            }
        }

        cloudtrail_history = (
            self._collect_instance_class_history(
                identifier=identifier,
                start=start,
                end=end,
            )
        )

        if cloudtrail_history:
            result["cloudtrail"] = (
                cloudtrail_history
            )

        return result

    def _collect_instance_class_history(
        self,
        identifier: str,
        start: datetime,
        end: datetime,
    ) -> Dict[str, Any]:

        """
        Find ModifyDBInstance events for the current
        RDS instance and extract instance-class changes.

        This is historical evidence only.

        DescribeDBInstances gives the current state.
        CloudTrail is used to reconstruct previous changes.
        """

        cloudtrail_profile = (
            self._profile_section(
                "cloudtrail"
            )
        )

        if not self._enabled(
            cloudtrail_profile,
            default=False,
        ):
            return {}

        events: List[
            Dict[str, Any]
        ] = []

        next_token: Optional[str] = None

        while True:

            params: Dict[str, Any] = {
                "LookupAttributes": [
                    {
                        "AttributeKey":
                            "EventName",

                        "AttributeValue":
                            "ModifyDBInstance",
                    }
                ],

                "StartTime":
                    start,

                "EndTime":
                    end,

                "MaxResults":
                    50,
            }

            if next_token:
                params["NextToken"] = (
                    next_token
                )

            response = (
                self.cloudtrail.lookup_events(
                    **params
                )
            )

            events.extend(
                response.get(
                    "Events",
                    [],
                )
            )

            next_token = (
                response.get(
                    "NextToken"
                )
            )

            if not next_token:
                break

        history: List[
            Dict[str, Any]
        ] = []

        classes: List[str] = []

        for event in events:

            event_name = event.get(
                "EventName"
            )

            if event_name != (
                "ModifyDBInstance"
            ):
                continue

            cloudtrail_event = (
                event.get(
                    "CloudTrailEvent"
                )
            )

            if not cloudtrail_event:
                continue

            try:
                import json

                parsed = json.loads(
                    cloudtrail_event
                )

            except (
                TypeError,
                ValueError,
            ):
                continue

            request_parameters = (
                parsed.get(
                    "requestParameters",
                    {},
                )
            )

            if not isinstance(
                request_parameters,
                dict,
            ):
                continue

            event_identifier = (
                request_parameters.get(
                    "dBInstanceIdentifier"
                )
                or
                request_parameters.get(
                    "DBInstanceIdentifier"
                )
            )

            if (
                event_identifier
                and event_identifier != identifier
            ):
                continue

            instance_class = (
                request_parameters.get(
                    "dBInstanceClass"
                )
                or
                request_parameters.get(
                    "DBInstanceClass"
                )
            )

            if not instance_class:
                continue

            instance_class = str(
                instance_class
            )

            if instance_class not in classes:
                classes.append(
                    instance_class
                )

            event_time = event.get(
                "EventTime"
            )

            history.append(
                {
                    "event_time":
                        (
                            event_time.isoformat()
                            if hasattr(
                                event_time,
                                "isoformat",
                            )
                            else str(
                                event_time
                            )
                        ),

                    "event_name":
                        "ModifyDBInstance",

                    "instance_class":
                        instance_class,

                    "username":
                        event.get(
                            "Username"
                        ),
                }
            )

        history.sort(
            key=lambda item:
                item.get(
                    "event_time",
                    "",
                )
        )

        return {
            "instance_class_history":
                classes,

            "events":
                history,

            "source":
                "cloudtrail",
        }