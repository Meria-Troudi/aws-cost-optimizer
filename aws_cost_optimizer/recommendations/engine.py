"""
NAT Gateway recommendation generation.
"""

from __future__ import annotations

from typing import Any


class RecommendationEngine:

    RULES = {
        "nat_gateway_no_activity":
            "_nat_no_activity",

        "nat_gateway_low_traffic":
            "_nat_low_traffic",

        "nat_gateway_aws_service_traffic":
            "_nat_aws_service",

        "nat_gateway_cross_az":
            "_nat_cross_az",

        "nat_gateway_endpoint_opportunity":
            "_nat_endpoint",
        "rds_no_activity":
            "_rds_no_activity",

        "rds_instance_possible_oversized":
            "_rds_oversized",

        "rds_multi_az_cost_review":
            "_rds_multi_az",

        "rds_excessive_backup_retention":
            "_rds_backup_retention",

        "rds_performance_insights_review":
            "_rds_performance_insights",

        "rds_io_intensive_workload":
            "_rds_io_intensive",

        "rds_old_instance_generation":
            "_rds_old_generation",

        "rds_underused_read_replica":
            "_rds_read_replica",

        "rds_billing_resource_mismatch":
            "_rds_billing_mismatch",

        "rds_unmatched_billing_usage":
            "_rds_unmatched_billing",

        "rds_aurora_cluster_context":
            "_rds_aurora_context",

        "rds_public_accessibility":
            "_rds_public_accessibility",

        # ============================================================
        # TRANSIT GATEWAY
        # ============================================================

        "transit_gateway_no_active_attachments":
            "_tgw_no_active_attachments",

        "transit_gateway_attachment_no_vpc_route":
            "_tgw_attachment_no_vpc_route",

        "transit_gateway_zero_observed_traffic":
            "_tgw_zero_observed_traffic",

        "transit_gateway_blackhole_routes":
            "_tgw_blackhole_routes",

        "vpc_endpoint_gateway_missing_route":
            "_endpoint_gateway_missing_route",

        "vpc_endpoint_interface_nat_path":
            "_endpoint_interface_nat_path",


        "elastic_ip_unassociated":
            "_elastic_ip_unassociated",
    }

    def generate(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        recommendations = []

        for finding in findings:

            handler_name = self.RULES.get(
                finding.get(
                    "finding_type"
                )
            )

            if not handler_name:
                continue

            handler = getattr(
                self,
                handler_name,
                None,
            )

            if not handler:
                continue

            recommendation = handler(
                finding
            )

            if recommendation:
                recommendations.append(
                    recommendation
                )

        return recommendations

    def _rds_no_activity(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review RDS instance with "
                "no observed activity"
            ),

            action=(
                "Validate whether the database is still "
                "required. Check application dependencies, "
                "scheduled workloads, and recovery requirements "
                "before stopping or deleting the instance."
            ),
        )

    #   

    def _rds_oversized(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        metadata = (
            finding.get(
                "metadata",
                [],
            )
        )

        instance_class = None

        if isinstance(
            metadata,
            list,
        ):

            for item in metadata:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                instance_class = item.get(
                    "instance_class"
                )

                if instance_class:
                    break

        if instance_class:

            action = (
                f"Review whether the {instance_class} "
                "instance class can be downsized based "
                "on sustained workload requirements."
            )

        else:

            action = (
                "Review whether the current RDS instance "
                "class can be downsized based on sustained "
                "workload requirements."
            )

        return self._build(
            finding=finding,

            title=(
                "Review potentially oversized "
                "RDS instance"
            ),

            action=action,
        )


    def _rds_multi_az(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review RDS Multi-AZ configuration"
            ),

            action=(
                "Validate whether the workload requires "
                "Multi-AZ availability. If the availability "
                "requirement allows it, evaluate whether "
                "Single-AZ would be appropriate."
            ),
        )

    #   

    def _rds_backup_retention(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review RDS backup retention"
            ),

            action=(
                "Review the database recovery requirements "
                "and reduce backup retention if the current "
                "retention period is higher than required."
            ),
        )
 

    def _rds_performance_insights(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review RDS Performance Insights"
            ),

            action=(
                "Validate whether Performance Insights "
                "is still required. Disable it if its "
                "monitoring capabilities are not needed."
            ),
        )


    def _rds_io_intensive(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review I/O-intensive RDS workload"
            ),

            action=(
                "Review IOPS, latency, and storage "
                "configuration before changing the "
                "instance size. Avoid blindly downsizing "
                "an I/O-dependent workload."
            ),
        )

    #   

    def _rds_old_generation(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Evaluate newer RDS instance generation"
            ),

            action=(
                "Compare the current instance generation "
                "with newer compatible generations and "
                "evaluate price/performance before migration."
            ),
        )

    #   

    def _rds_read_replica(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review underused RDS read replica"
            ),

            action=(
                "Validate whether the read replica is "
                "still required. If it is not serving "
                "a required workload or availability "
                "purpose, evaluate resizing or removal."
            ),
        )

    #   

    def _rds_billing_mismatch(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        metadata = (
            finding.get(
                "metadata",
                [],
            )
        )

        billing_class = None
        actual_class = None

        if isinstance(
            metadata,
            list,
        ):

            for item in metadata:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                billing_class = item.get(
                    "billing_instance_class"
                )

                actual_class = item.get(
                    "actual_instance_class"
                )

                if (
                    billing_class
                    or actual_class
                ):
                    break

        if (
            billing_class
            and actual_class
        ):

            reason = (
                f"Billing identifies {billing_class}, "
                f"while discovery identifies "
                f"{actual_class}. Reconcile the "
                "billing attribution before right-sizing."
            )

        else:

            reason = finding.get(
                "reason",
                "",
            )

        return self._build(
            finding=finding,

            title=(
                "Reconcile RDS billing and "
                "resource attribution"
            ),

            action=(
                "Validate the billing usage type against "
                "the actual RDS resource and cluster "
                "configuration before right-sizing."
            ),

            reason=reason,
        )

    def _rds_unmatched_billing(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        metadata = finding.get("metadata") or []
        billing_class = None
        billing_cost = None
        region = finding.get("scope")

        if isinstance(metadata, list):
            for item in metadata:
                if isinstance(item, dict):
                    billing_class = item.get("billing_instance_class")
                    billing_cost = item.get("billing_cost")
                    region = item.get("region") or region
                    if billing_class:
                        break

        cost_text = (
            f"${float(billing_cost):,.2f} "
            if billing_cost is not None
            else ""
        )

        reason = finding.get("reason") or (
            f"{cost_text}of RDS usage is billed as {billing_class}, "
            f"but no currently discovered {billing_class} RDS instance "
            f"exists in {region or 'the scanned region'}."
        )

        return self._build(
            finding=finding,
            title="Review unmatched RDS billing usage",
            action=(
                "Review historical RDS resources and billing dimensions "
                "before attributing this cost to a current RDS instance."
            ),
            reason=reason,
        )

    #   

    def _rds_aurora_context(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review Aurora cluster context "
                "before optimizing"
            ),

            action=(
                "Evaluate the Aurora writer, readers, "
                "cluster workload, and failover "
                "requirements together before resizing "
                "or removing an instance."
            ),
        )

    #   

    def _rds_public_accessibility(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return {
            "finding_id":
                finding.get(
                    "database_id"
                ),

            "title":
                "Review publicly accessible RDS instance",

            "resource_type":
                finding.get(
                    "resource_type"
                ),

            "priority":
                finding.get(
                    "severity"
                ),

            "confidence":
                finding.get(
                    "confidence"
                ),

      
            "reason":
                finding.get(
                    "reason",
                    "",
                ),

            "action":
                (
                    "Review whether public accessibility "
                    "is required and restrict network "
                    "access where possible."
                ),

            "affected_resources":
                finding.get(
                    "resource_ids",
                    [],
                ),

            "category":
                "security",
        }
    def _nat_no_activity(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review NAT Gateways with "
                "no observed activity"
            ),

            action=(
                "Validate the workloads and routes "
                "that reference these NAT Gateways. "
                "Remove a NAT Gateway only when its "
                "network dependency is no longer required."
            ),
           
        )

 

    def _nat_low_traffic(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        traffic = (
            finding
            .get("aggregate_evidence", {})
            .get("traffic_gib_total")
        )

        reason = finding.get(
            "reason",
            "",
        )

        if traffic is not None:

            reason = (
                f"NAT Gateway traffic was "
                f"approximately {traffic:.4f} GiB "
                "during the observation period."
            )

        return self._build(
            finding=finding,

            title=(
                "Review low-traffic "
                "NAT Gateways"
            ),

            action=(
                "Review whether the current NAT "
                "Gateway architecture is justified "
                "by the observed traffic."
            ),

            reason=reason,
        )

 

    def _nat_aws_service(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        services = (
            self._metadata_values(
                finding,
                "services",
            )
        )

        if services:

            action = (
                "Evaluate whether traffic to "
                f"{', '.join(services)} can use "
                "VPC endpoints instead of traversing "
                "the NAT Gateway."
            )

        else:

            action = (
                "Evaluate whether the identified "
                "AWS service traffic can use "
                "VPC endpoints."
            )

        return self._build(
            finding=finding,

            title=(
                "Review AWS service traffic "
                "through NAT Gateway"
            ),

            action=action,
        )


    def _nat_cross_az(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,

            title=(
                "Review cross-AZ NAT Gateway routing"
            ),

            action=(
                "Evaluate NAT Gateway placement and "
                "route paths so traffic can remain "
                "within the appropriate Availability "
                "Zone where practical."
            ),
        )


    def _nat_endpoint(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        services = (
            self._metadata_values(
                finding,
                "candidate_services",
            )
        )

        if services:

            action = (
                "Evaluate VPC endpoints for "
                f"{', '.join(services)} and determine "
                "whether the corresponding traffic "
                "can bypass the NAT Gateway."
            )

        else:

            action = (
                "Evaluate VPC endpoints for the "
                "identified AWS service traffic."
            )

        return self._build(
            finding=finding,

            title=(
                "Evaluate VPC endpoint "
                "opportunities for NAT traffic"
            ),

            action=action,
        )

    #   
    # TRANSIT GATEWAY
    #   

    def _tgw_no_active_attachments(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        return self._build(
            finding=finding,
            title=(
                "Review Transit Gateway with "
                "no active attachments"
            ),
            action=(
                "Validate whether the Transit Gateway is "
                "still required. If no VPC, VPN, peering, or "
                "other active attachment depends on it, "
                "evaluate whether it can be removed."
            ),
        )

    def _tgw_attachment_no_vpc_route(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        vpc_id = self._metadata_value(finding, "vpc_id")
        attachment_id = self._metadata_value(
            finding,
            "attachment_id",
        )

        if vpc_id and attachment_id:
            reason = (
                f"VPC {vpc_id} is attached through "
                f"{attachment_id}, but no route targeting "
                "the Transit Gateway was detected."
            )
        else:
            reason = finding.get("reason", "")

        return self._build(
            finding=finding,
            title=(
                "Review Transit Gateway attachment "
                "with no VPC route"
            ),
            action=(
                "Validate whether the attachment is still "
                "required. If it is required, review the "
                "VPC route configuration. If it is not "
                "required, evaluate whether the attachment "
                "can be removed."
            ),
            reason=reason,
        )

    def _tgw_zero_observed_traffic(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        attachment_count = self._metadata_value(
            finding,
            "active_vpc_attachment_count",
        )
        total_bytes = self._metadata_value(
            finding,
            "total_bytes",
        )

        if total_bytes is not None:
            reason = (
                f"No Transit Gateway traffic was observed "
                f"during the analysis period "
                f"(total bytes: {total_bytes})."
            )
        else:
            reason = finding.get("reason", "")

        if attachment_count is not None and total_bytes is None:
            reason = finding.get("reason", reason)

        return self._build(
            finding=finding,
            title=(
                "Review Transit Gateway with "
                "zero observed traffic"
            ),
            action=(
                "Validate whether the active attachments "
                "are still required, including scheduled, "
                "intermittent, and failover workloads. "
                "If the attachments are no longer required, "
                "evaluate removing them and the Transit Gateway."
            ),
            reason=reason,
        )

    def _tgw_blackhole_routes(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        route_count = None
        metadata = finding.get("metadata")

        blackhole_routes = None
        if isinstance(metadata, dict):
            blackhole_routes = metadata.get("blackhole_routes")
        elif isinstance(metadata, list):
            for item in metadata:
                if isinstance(item, dict):
                    blackhole_routes = item.get("blackhole_routes")
                    if blackhole_routes is not None:
                        break

        if isinstance(blackhole_routes, list):
            route_count = len(blackhole_routes)

        if route_count is not None:
            reason = (
                f"{route_count} blackhole route(s) were "
                "detected in the Transit Gateway route tables."
            )
        else:
            reason = finding.get("reason", "")

        return self._build(
            finding=finding,
            title=(
                "Review Transit Gateway "
                "blackhole routes"
            ),
            action=(
                "Review the affected routes and their "
                "associated attachments. Remove obsolete "
                "routes or attachments only after confirming "
                "they are no longer required."
            ),
            reason=reason,
        )
    def _endpoint_gateway_missing_route(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        services = self._metadata_values(
            finding,
            "service_name",
        )

        if services:
            reason = (
                f"Gateway endpoint for "
                f"{', '.join(services)} has no detected "
                "route targeting the endpoint."
            )
        else:
            reason = finding.get("reason", "")

        return self._build(
            finding=finding,
            title=(
                "Review Gateway VPC Endpoint routing"
            ),
            action=(
                "Review the route tables associated with "
                "the Gateway endpoint. If the endpoint is "
                "intended to provide private access to the "
                "service, ensure the required endpoint "
                "routes are configured."
            ),
            reason=reason,
        )

    def _endpoint_interface_nat_path(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        services = self._metadata_values(
            finding,
            "service_name",
        )

        if services:
            reason = (
                f"Interface endpoint for "
                f"{', '.join(services)} exists while "
                "NAT Gateway routing is also present "
                "in the detected network path."
            )
        else:
            reason = finding.get("reason", "")

        return self._build(
            finding=finding,
            title=(
                "Review Interface VPC Endpoint "
                "and NAT Gateway routing"
            ),
            action=(
                "Validate whether the workload traffic "
                "can use the Interface endpoint directly "
                "instead of NAT Gateway routing. Review "
                "the endpoint, route tables, and workload "
                "dependencies before changing either path."
            ),
            reason=reason,
        )

    #   
    # ELASTIC IP
    #   

    def _elastic_ip_unassociated(
        self,
        finding: dict[str, Any],
    ) -> dict[str, Any]:

        public_ip = self._metadata_value(finding, "public_ip")
        allocation_id = self._metadata_value(
            finding,
            "allocation_id",
        )

        if public_ip and allocation_id:
            reason = (
                f"Elastic IP {public_ip} "
                f"({allocation_id}) is not associated "
                "with a resource."
            )
        else:
            reason = finding.get("reason", "")

        return self._build(
            finding=finding,
            title=(
                "Review unassociated Elastic IP"
            ),
            action=(
                "Release the Elastic IP if it is no longer "
                "required. Validate future workload, DNS, "
                "failover, and infrastructure dependencies "
                "before releasing it."
            ),
            reason=reason,
        )

    @staticmethod
    def _build(
        *,
        finding: dict[str, Any],
        title: str,
        action: str,
        reason: str | None = None,
    ) -> dict[str, Any]:

        return {
            "finding_id":
                finding.get(
                    "database_id"
                ),

            "title":
                title,

            "resource_type":
                finding.get(
                    "resource_type"
                ),

            "priority":
                finding.get(
                    "severity"
                ),

            "confidence":
                finding.get(
                    "confidence"
                ),

  

            "reason":
                reason
                or finding.get(
                    "reason",
                    "",
                ),

            "action":
                action,

            "affected_resources":
                finding.get(
                    "resource_ids",
                    [],
                ),
        }

 

    @staticmethod
    def _metadata_values(
        finding: dict[str, Any],
        key: str,
    ) -> list[str]:

        values: list[str] = []
        metadata = finding.get("metadata")

        if isinstance(metadata, dict):
            raw_value = metadata.get(key)

            if isinstance(raw_value, list):
                for element in raw_value:
                    string_value = str(element)
                    if string_value not in values:
                        values.append(string_value)
            elif raw_value is not None:
                values.append(str(raw_value))

            return values

        if isinstance(metadata, list):
            for item in metadata:
                if not isinstance(item, dict):
                    continue

                raw_value = item.get(key)

                if isinstance(raw_value, list):
                    for element in raw_value:
                        string_value = str(element)
                        if string_value not in values:
                            values.append(string_value)
                elif raw_value is not None:
                    string_value = str(raw_value)
                    if string_value not in values:
                        values.append(string_value)

        return values

    @staticmethod
    def _metadata_value(
        finding: dict[str, Any],
        key: str,
    ) -> Any:
        values = RecommendationEngine._metadata_values(
            finding,
            key,
        )
        if not values:
            metadata = finding.get("metadata")
            if isinstance(metadata, dict):
                return metadata.get(key)
            if isinstance(metadata, list):
                for item in metadata:
                    if isinstance(item, dict) and key in item:
                        return item.get(key)
            return None
        if len(values) == 1:
            return values[0]
        return values