"""
AWS Transit Gateway collector.

Collection strategy
-------------------

Transit Gateway collection is cost-driven.

Primary billing drivers:

1. TransitGateway-Hours
   -> collect Transit Gateway identity and attachment inventory.

2. TransitGateway-Bytes
   -> collect Transit Gateway and attachment-level traffic
      when configured in the collection profile.

Optional topology evidence:

3. Route tables
4. Routes
5. Associations
6. Propagations

These are collected only when explicitly requested by the
collection profile.

The collector never makes optimization decisions.
It only produces evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_cost_optimizer.collection.base import BaseCollector
from aws_cost_optimizer.collection.metrics.cloudwatch import (
    CloudWatchMetricCollector,
)
from aws_cost_optimizer.config.client import get_client

from collection.registry import register


@register
class TransitGatewayCollector(BaseCollector):

    key = "transit_gateway"
    resource_type = "transit_gateway"

    def __init__(
        self,
        scan,
        region: str | None = None,
        profile: Dict[str, Any] | None = None,
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

        self.cloudwatch_collector = CloudWatchMetricCollector(
            cloudwatch=self.cloudwatch,
        )

    # PROFILE

    def _profile_section(
        self,
        name: str,
    ) -> Dict[str, Any]:

        value = self.profile.get(name, {})

        if not isinstance(value, dict):
            return {}

        return value

    @staticmethod
    def _config_enabled(
        section: Dict[str, Any],
        default: bool = False,
    ) -> bool:
        """
        Whether an already-resolved profile section dict (e.g.
        self._profile_section("identity")) declares itself enabled.

        Deliberately named differently from BaseCollector._section_enabled
        (self, section_name: str) -- that one looks up a section BY NAME
        in self.profile; this one checks a dict the caller already
        resolved. They used to share the name "_section_enabled", which
        meant this override silently shadowed the base method for every
        Transit Gateway resource: _safe_collect_section() calls
        self._section_enabled("identity"), and passing that string into
        this method's `section: Dict` parameter crashed on
        section.get("enabled") with 'str' object has no attribute 'get'
        -- collection never actually failed per-resource, it failed for
        every single Transit Gateway, unconditionally, on the very first
        section (same bug independently present in EC2Collector).
        """

        value = section.get("enabled")

        if value is None:
            return default

        return value is True

    def _requested_relationships(self) -> set[str]:

        section = self._profile_section("relationships")

        if not self._config_enabled(
            section,
            default=False,
        ):
            return set()

        values = section.get(
            "collect",
            [],
        )

        if not isinstance(values, list):
            return set()

        return {str(value).strip().lower() for value in values if str(value).strip()}

    def _cloudwatch_enabled(self) -> bool:

        observations = self._profile_section("observations")

        if not self._config_enabled(
            observations,
            default=False,
        ):
            return False

        cloudwatch = observations.get(
            "cloudwatch",
            {},
        )

        if not isinstance(cloudwatch, dict):
            return False

        return cloudwatch.get("enabled") is True

    def _metric_specs(
        self,
        scope: str | None = None,
    ) -> List[Dict[str, Any]]:

        cloudwatch = self.cloudwatch_profile()

        values = cloudwatch.get(
            "metrics",
            [],
        )

        if not isinstance(values, list):
            return []

        result: List[Dict[str, Any]] = []

        requested_scope = str(scope).strip().lower() if scope else None

        for item in values:

            if not isinstance(item, dict):
                continue

            name = str(item.get("name") or "").strip()

            if not name:
                continue

            scopes = item.get(
                "scopes",
                [],
            )

            if requested_scope:

                if not isinstance(
                    scopes,
                    list,
                ):
                    continue

                normalized_scopes = {
                    str(value).strip().lower() for value in scopes if str(value).strip()
                }

                if requested_scope not in normalized_scopes:
                    continue

            spec = dict(item)

            spec["statistic"] = item.get(
                "statistic",
                "Sum",
            )

            result.append(spec)

        return result

    # DISCOVERY

    def _allowed_gateway_states(self) -> set[str]:

        states = self._profile_section("states")

        operational = states.get(
            "operational_states",
            [],
        )

        transitional = states.get(
            "transitional_states",
            [],
        )

        allowed = []

        if isinstance(
            operational,
            list,
        ):
            allowed.extend(operational)

        if isinstance(
            transitional,
            list,
        ):
            allowed.extend(transitional)

        normalized = {
            str(value).strip().lower() for value in allowed if str(value).strip()
        }

        # Backward-compatible fallback.
        if not normalized:

            normalized = {
                "available",
                "pending",
            }

        return normalized

    def discover(self) -> list:

        allowed = self._allowed_gateway_states()

        response = self.ec2.describe_transit_gateways()

        result = []

        for gateway in response.get(
            "TransitGateways",
            [],
        ):

            if not isinstance(
                gateway,
                dict,
            ):
                continue

            state = str(gateway.get("State") or "").strip().lower()

            if allowed and state not in allowed:
                continue

            result.append(gateway)

        return result

    # RESOURCE ID

    def get_resource_id(
        self,
        resource: dict,
    ) -> str:

        value = resource.get("TransitGatewayId")

        if not value:
            raise ValueError("Transit Gateway ID is missing.")

        return str(value)

    # IDENTITY

    def collect_identity(
        self,
        resource: dict,
    ) -> dict:

        section = self._profile_section("identity")

        if not self._config_enabled(
            section,
            default=False,
        ):
            return {
                "status": "disabled",
            }

        fields = section.get(
            "fields",
            [],
        )

        result = {
            "status": "ok",
        }

        if not isinstance(
            fields,
            list,
        ):
            return result

        for field in fields:

            if not isinstance(
                field,
                dict,
            ):
                continue

            source = field.get("source")

            output = field.get("output")

            if not source or not output:
                continue

            result[str(output)] = self._get_nested_value(
                resource,
                str(source),
            )

        return result

    # CONFIGURATION

    def collect_configuration(
        self,
        resource: dict,
    ) -> dict:

        section = self._profile_section("configuration")

        if not self._config_enabled(
            section,
            default=False,
        ):
            return {
                "status": "disabled",
            }

        fields = section.get(
            "fields",
            [],
        )

        result = {
            "status": "ok",
        }

        if not isinstance(
            fields,
            list,
        ):
            return result

        for field in fields:

            if not isinstance(
                field,
                dict,
            ):
                continue

            source = field.get("source")

            output = field.get("output")

            if not source or not output:
                continue

            result[str(output)] = self._get_nested_value(
                resource,
                str(source),
            )

        return result

    # ATTACHMENTS

    def _collect_attachments(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        response = self.ec2.describe_transit_gateway_attachments(
            Filters=[
                {
                    "Name": "transit-gateway-id",
                    "Values": [
                        transit_gateway_id,
                    ],
                }
            ]
        )

        attachments = response.get(
            "TransitGatewayAttachments",
            [],
        )

        result = []

        for attachment in attachments:

            if not isinstance(
                attachment,
                dict,
            ):
                continue

            attachment_id = attachment.get("TransitGatewayAttachmentId")

            resource_id = attachment.get("ResourceId")

            resource_type = str(attachment.get("ResourceType") or "").strip().lower()

            result.append(
                {
                    "status": "ok",
                    "attachment_id": attachment_id,
                    "transit_gateway_attachment_id": attachment_id,
                    "transit_gateway_id": attachment.get("TransitGatewayId"),
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "state": attachment.get("State"),
                    "creation_time": attachment.get("CreationTime"),
                    "association": attachment.get("Association"),
                    "tags": attachment.get(
                        "Tags",
                        [],
                    ),
                    "classification": self._classify_attachment(resource_type),
                }
            )

        return result

    def _classify_attachment(
        self,
        resource_type: str,
    ) -> str:

        section = self._profile_section("attachment_types")

        normalized_type = str(resource_type).strip().lower()

        for classification in (
            "vpc",
            "peering",
            "other",
        ):

            values = section.get(
                classification,
                [],
            )

            if not isinstance(
                values,
                list,
            ):
                continue

            normalized = {
                str(value).strip().lower() for value in values if str(value).strip()
            }

            if normalized_type in normalized:
                return classification

        return "other"

    # ROUTE TABLES

    def _collect_route_tables(
        self,
        transit_gateway_id: str,
    ) -> List[Dict[str, Any]]:

        values = self._paginate(
            self.ec2.describe_transit_gateway_route_tables,
            request_kwargs={
                "Filters": [
                    {
                        "Name": "transit-gateway-id",
                        "Values": [
                            transit_gateway_id,
                        ],
                    }
                ]
            },
            result_key="TransitGatewayRouteTables",
        )

        result = []

        for item in values:

            result.append(
                {
                    "status": "ok",
                    "transit_gateway_route_table_id": item.get(
                        "TransitGatewayRouteTableId"
                    ),
                    "transit_gateway_id": item.get("TransitGatewayId"),
                    "state": item.get("State"),
                    "default_association_route_table": item.get(
                        "DefaultAssociationRouteTable"
                    ),
                    "default_propagation_route_table": item.get(
                        "DefaultPropagationRouteTable"
                    ),
                    "creation_time": item.get("CreationTime"),
                    "tags": item.get(
                        "Tags",
                        [],
                    ),
                }
            )

        return result

    # ROUTES

    def _collect_routes(
        self,
        route_table_id: str,
    ) -> Dict[str, Any]:

        routes = self._paginate(
            self.ec2.search_transit_gateway_routes,
            request_kwargs={
                "TransitGatewayRouteTableId": route_table_id,
                "Filters": [],
            },
            result_key="Routes",
        )

        normalized = []

        for route in routes:

            normalized.append(
                {
                    "status": "ok",
                    "route_table_id": route_table_id,
                    "destination_cidr_block": route.get("DestinationCidrBlock"),
                    "prefix_list_id": route.get("PrefixListId"),
                    "type": route.get("Type"),
                    "state": route.get("State"),
                    "attachment_ids": route.get(
                        "TransitGatewayAttachments",
                        [],
                    ),
                }
            )

        blackholes = sum(
            1
            for item in normalized
            if str(item.get("state") or "").strip().lower() == "blackhole"
        )

        return {
            "status": "ok",
            "route_table_id": route_table_id,
            "route_count": len(normalized),
            "blackhole_route_count": blackholes,
            "routes": normalized,
        }

    # ASSOCIATIONS

    def _collect_associations(
        self,
        route_table_id: str,
    ) -> Dict[str, Any]:

        values = self._paginate(
            self.ec2.get_transit_gateway_route_table_associations,
            request_kwargs={
                "TransitGatewayRouteTableId": route_table_id,
            },
            result_key="Associations",
        )

        normalized = []

        for item in values:

            normalized.append(
                {
                    "status": "ok",
                    "attachment_id": item.get("TransitGatewayAttachmentId"),
                    "transit_gateway_attachment_id": item.get(
                        "TransitGatewayAttachmentId"
                    ),
                    "route_table_id": route_table_id,
                    "resource_id": item.get("ResourceId"),
                    "state": item.get("State"),
                    "resource_type": item.get("ResourceType"),
                }
            )

        return {
            "status": "ok",
            "route_table_id": route_table_id,
            "association_count": len(normalized),
            "associations": normalized,
        }

    # PROPAGATIONS

    def _collect_propagations(
        self,
        route_table_id: str,
    ) -> Dict[str, Any]:

        values = self._paginate(
            self.ec2.get_transit_gateway_route_table_propagations,
            request_kwargs={
                "TransitGatewayRouteTableId": route_table_id,
            },
            result_key="TransitGatewayRouteTablePropagations",
        )

        normalized = []

        for item in values:

            normalized.append(
                {
                    "status": "ok",
                    "attachment_id": item.get("TransitGatewayAttachmentId"),
                    "transit_gateway_attachment_id": item.get(
                        "TransitGatewayAttachmentId"
                    ),
                    "route_table_id": route_table_id,
                    "resource_id": item.get("ResourceId"),
                    "state": item.get("State"),
                    "resource_type": item.get("ResourceType"),
                }
            )

        return {
            "status": "ok",
            "route_table_id": route_table_id,
            "propagation_count": len(normalized),
            "propagations": normalized,
        }

    # RELATIONSHIPS

    def collect_relationships(
        self,
        resource: dict,
    ) -> dict:

        section = self._profile_section("relationships")

        if not self._config_enabled(
            section,
            default=False,
        ):
            return {
                "status": "disabled",
            }

        tgw_id = self.get_resource_id(resource)

        requested = self._requested_relationships()

        attachments_requested = bool(
            requested
            & {
                "attachments",
                "vpc_attachments",
                "peering_attachments",
                "other_attachments",
            }
        )

        route_tables_requested = bool(
            requested
            & {
                "route_tables",
                "routes",
                "associations",
                "propagations",
            }
        )

        routes_requested = "routes" in requested

        associations_requested = "associations" in requested

        propagations_requested = "propagations" in requested

        relationships = {
            "status": "ok",
            "transit_gateway_id": tgw_id,
            "attachments": [],
            "vpc_attachments": [],
            "peering_attachments": [],
            "other_attachments": [],
            "route_tables": [],
            "routes": [],
            "associations": [],
            "propagations": [],
            "collection_status": {
                "attachments_requested": attachments_requested,
                "attachments_complete": None,
                "route_tables_requested": route_tables_requested,
                "route_tables_complete": None,
                "routes_requested": routes_requested,
                "routes_complete": None,
                "association_evidence_requested": associations_requested,
                "association_evidence_complete": None,
                "propagation_evidence_requested": propagations_requested,
                "propagation_evidence_complete": None,
            },
        }

        errors = {}

        # Attachments

        if attachments_requested:

            try:

                attachments = self._collect_attachments(tgw_id)

                relationships["attachments"] = attachments

                relationships["vpc_attachments"] = [
                    item for item in attachments if item.get("classification") == "vpc"
                ]

                relationships["peering_attachments"] = [
                    item
                    for item in attachments
                    if item.get("classification") == "peering"
                ]

                relationships["other_attachments"] = [
                    item
                    for item in attachments
                    if item.get("classification") == "other"
                ]

                relationships["collection_status"]["attachments_complete"] = True

            except Exception as exc:

                errors["attachments"] = str(exc)

                relationships["collection_status"]["attachments_complete"] = False

        # Route tables

        route_tables = []

        if route_tables_requested:

            try:

                route_tables = self._collect_route_tables(tgw_id)

                relationships["route_tables"] = route_tables

                relationships["collection_status"]["route_tables_complete"] = True

            except Exception as exc:

                errors["route_tables"] = str(exc)

                relationships["collection_status"]["route_tables_complete"] = False

        # Routes

        if routes_requested:

            if not route_tables_requested:

                relationships["collection_status"]["routes_complete"] = False

                errors["routes"] = (
                    "Routes requested but route tables " "were not requested."
                )

            else:

                try:

                    relationships["routes"] = [
                        self._collect_routes(item["transit_gateway_route_table_id"])
                        for item in route_tables
                        if item.get("transit_gateway_route_table_id")
                    ]

                    relationships["collection_status"]["routes_complete"] = True

                except Exception as exc:

                    errors["routes"] = str(exc)

                    relationships["collection_status"]["routes_complete"] = False

        # Associations

        if associations_requested:

            if not route_tables_requested:

                relationships["collection_status"][
                    "association_evidence_complete"
                ] = False

                errors["associations"] = (
                    "Associations requested but route tables " "were not requested."
                )

            else:

                try:

                    relationships["associations"] = [
                        self._collect_associations(
                            item["transit_gateway_route_table_id"]
                        )
                        for item in route_tables
                        if item.get("transit_gateway_route_table_id")
                    ]

                    relationships["collection_status"][
                        "association_evidence_complete"
                    ] = True

                except Exception as exc:

                    errors["associations"] = str(exc)

                    relationships["collection_status"][
                        "association_evidence_complete"
                    ] = False

        # Propagations

        if propagations_requested:

            if not route_tables_requested:

                relationships["collection_status"][
                    "propagation_evidence_complete"
                ] = False

                errors["propagations"] = (
                    "Propagations requested but route tables " "were not requested."
                )

            else:

                try:

                    relationships["propagations"] = [
                        self._collect_propagations(
                            item["transit_gateway_route_table_id"]
                        )
                        for item in route_tables
                        if item.get("transit_gateway_route_table_id")
                    ]

                    relationships["collection_status"][
                        "propagation_evidence_complete"
                    ] = True

                except Exception as exc:

                    errors["propagations"] = str(exc)

                    relationships["collection_status"][
                        "propagation_evidence_complete"
                    ] = False

        if errors:

            relationships["status"] = "partial"

            relationships["errors"] = errors

        return relationships

    # CLOUDWATCH

    def collect_observations(
        self,
        resource: dict,
    ) -> dict:

        if not self._cloudwatch_enabled():

            return {
                "status": "disabled",
            }

        tgw_id = self.get_resource_id(resource)

        start, end = self.get_analysis_period()

        gateway_specs = self._metric_specs(scope="gateway")

        attachment_specs = self._metric_specs(scope="attachment")

        if not gateway_specs and not attachment_specs:

            return {
                "status": "empty",
                "reason": "No CloudWatch metrics configured.",
            }

        # Gateway metrics

        gateway_results = []

        if gateway_specs:

            gateway_dimensions = [
                {
                    "Name": "TransitGateway",
                    "Value": tgw_id,
                }
            ]

            gateway_results = self.cloudwatch_collector.collect(
                namespace=(self.cloudwatch_namespace()),
                dimensions=gateway_dimensions,
                metric_specs=gateway_specs,
                start=start,
                end=end,
                requested_period=(self.cloudwatch_period()),
            )

            self._attach_metric_roles(
                gateway_results,
                gateway_specs,
            )

        # Attachment metrics

        attachment_results = {}
        attachment_error = None
        attachment_count = 0

        if attachment_specs:

            try:

                attachments = self._collect_attachments(tgw_id)

            except Exception as exc:

                attachments = []
                attachment_error = str(exc)

            requests = []

            for attachment in attachments:

                attachment_id = attachment.get("attachment_id")

                if not attachment_id:
                    continue

                requests.append(
                    {
                        "resource_key": str(attachment_id),
                        "namespace": self.cloudwatch_namespace(),
                        "dimensions": [
                            {
                                "Name": "TransitGatewayAttachment",
                                "Value": str(attachment_id),
                            }
                        ],
                        "metric_specs": attachment_specs,
                    }
                )

            attachment_count = len(requests)

            if requests:

                attachment_results = self.cloudwatch_collector.collect_batch(
                    requests=requests,
                    start=start,
                    end=end,
                    requested_period=(self.cloudwatch_period()),
                )

                for values in attachment_results.values():

                    self._attach_metric_roles(
                        values,
                        attachment_specs,
                    )

        return {
            "status": "partial" if attachment_error else "ok",
            "analysis_start": start.isoformat(),
            "analysis_end": end.isoformat(),
            "cloudwatch": {
                "namespace": self.cloudwatch_namespace(),
                "gateway": {
                    "resource_id": tgw_id,
                    "metrics": {
                        item.get("metric_key"): item
                        for item in gateway_results
                        if isinstance(
                            item,
                            dict,
                        )
                        and item.get("metric_key")
                    },
                },
                "attachments": {
                    str(resource_id): {
                        item.get("metric_key"): item
                        for item in values
                        if isinstance(
                            item,
                            dict,
                        )
                        and item.get("metric_key")
                    }
                    for resource_id, values in attachment_results.items()
                },
                "attachment_collection": {
                    "requested_count": attachment_count,
                    "returned_count": len(attachment_results),
                    "complete": (
                        attachment_error is None
                        and len(attachment_results) == attachment_count
                    ),
                    "error": attachment_error,
                },
            },
        }

    # OPTIMIZATION EVIDENCE

    def build_optimization_evidence(
        self,
        resource: dict,
        collected_resource: dict,
    ) -> dict:

        relationships = collected_resource.get(
            "relationships",
            {},
        )

        observations = collected_resource.get(
            "observations",
            {},
        )

        evidence = {
            "status": "ok",
            "resource_type": self.resource_type,
            "resource_id": self.get_resource_id(resource),
        }

        # Attachments

        attachments = relationships.get("attachments")

        if isinstance(
            attachments,
            list,
        ):

            evidence["attachment_count"] = len(attachments)

            evidence["active_attachment_count"] = sum(
                1
                for item in attachments
                if str(item.get("state") or "").strip().lower() == "available"
            )

            classification_counts = {
                "vpc": 0,
                "peering": 0,
                "other": 0,
            }

            for item in attachments:

                classification = item.get("classification")

                if classification in (classification_counts):
                    classification_counts[classification] += 1

            evidence["attachment_types"] = classification_counts

        else:

            evidence["attachment_count"] = None

            evidence["active_attachment_count"] = None

            evidence["attachment_types"] = {}

        # CloudWatch

        cloudwatch = (
            observations.get(
                "cloudwatch",
                {},
            )
            if isinstance(
                observations,
                dict,
            )
            else {}
        )

        gateway = (
            cloudwatch.get(
                "gateway",
                {},
            )
            if isinstance(
                cloudwatch,
                dict,
            )
            else {}
        )

        evidence["gateway_metrics"] = self._extract_metric_evidence(
            gateway.get(
                "metrics",
                {},
            )
        )

        evidence["attachment_metrics"] = self._extract_attachment_metric_evidence(
            cloudwatch.get(
                "attachments",
                {},
            )
        )

        # Collection status

        evidence["collection_status"] = relationships.get(
            "collection_status",
            {},
        )

        return evidence

    # HELPERS

    @staticmethod
    def _attach_metric_roles(
        results,
        specs,
    ):

        roles = {
            str(item.get("key") or item.get("name")): item.get("role")
            for item in specs
            if isinstance(
                item,
                dict,
            )
        }

        for result in results:

            if not isinstance(
                result,
                dict,
            ):
                continue

            key = result.get("metric_key")

            if key in roles:

                result["role"] = roles[key]

    @staticmethod
    def _extract_metric_evidence(
        metrics,
    ):

        if not isinstance(
            metrics,
            dict,
        ):
            return {}

        result = {}

        for key, metric in metrics.items():

            if not isinstance(
                metric,
                dict,
            ):
                continue

            result[key] = {
                "status": metric.get("status"),
                "has_data": metric.get("has_data"),
                "value": metric.get("value"),
                "total": metric.get("total"),
                "sum": metric.get("sum"),
                "samples": metric.get("samples"),
                "complete": metric.get("complete"),
                "role": metric.get("role"),
                "analysis_start": metric.get("analysis_start"),
                "analysis_end": metric.get("analysis_end"),
            }

        return result

    @classmethod
    def _extract_attachment_metric_evidence(
        cls,
        attachments,
    ):

        if not isinstance(
            attachments,
            dict,
        ):
            return {}

        return {
            str(attachment_id): cls._extract_metric_evidence(metrics)
            for attachment_id, metrics in attachments.items()
        }

    @staticmethod
    def _get_nested_value(
        data,
        path,
    ):

        current = data

        for part in path.split("."):

            if not isinstance(
                current,
                dict,
            ):
                return None

            current = current.get(part)

        return current

    @staticmethod
    def _paginate(
        method,
        *,
        request_kwargs,
        result_key,
    ):

        result = []

        kwargs = dict(request_kwargs)

        while True:

            response = method(**kwargs)

            page = response.get(
                result_key,
                [],
            )

            if isinstance(
                page,
                list,
            ):

                result.extend(
                    item
                    for item in page
                    if isinstance(
                        item,
                        dict,
                    )
                )

            token = response.get("NextToken")

            if not token:
                break

            kwargs["NextToken"] = token

        return result
