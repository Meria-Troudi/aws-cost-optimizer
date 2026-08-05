"""
Transit Gateway Collector
"""

from aws.client import get_client

from collectors.base import BaseCollector
from collectors.registry import register


@register
class TransitGatewayCollector(BaseCollector):

    key = "transit_gateway"

    def collect(self):

        ec2 = get_client(
            "ec2",
            self.region
        )

        tgw_response = ec2.describe_transit_gateways()

        gateways = tgw_response.get(
            "TransitGateways",
            []
        )

        print(
            f"[{self.region}] Transit gateways discovered: {len(gateways)}"
        )

        resources = []

        for tgw in gateways:

            tgw_id = tgw[
                "TransitGatewayId"
            ]

            attachment_response = (
                ec2.describe_transit_gateway_attachments(
                    Filters=[
                        {
                            "Name": "transit-gateway-id",
                            "Values": [tgw_id]
                        }
                    ]
                )
            )

            attachments = (
                attachment_response
                .get(
                    "TransitGatewayAttachments",
                    []
                )
            )

            resources.append({
                "resource_id": tgw_id,
                "resource_type": "transit_gateway",
                "region": self.region,
                "state": tgw.get("State"),
                "name": tgw_id,
                "tags": {
                    t["Key"]: t["Value"]
                    for t in tgw.get("Tags", [])
                },
                "attributes": {
                    "amazon_side_asn": tgw.get(
                        "Options",
                        {}
                    ).get("AmazonSideAsn"),
                    "default_route_table_association": tgw.get(
                        "Options",
                        {}
                    ).get("DefaultRouteTableAssociation"),
                    "default_route_table_propagation": tgw.get(
                        "Options",
                        {}
                    ).get("DefaultRouteTablePropagation"),
                    "attachments_count": len(attachments),
                    "attachments": [
                        {
                            "id": a["TransitGatewayAttachmentId"],
                            "type": a["ResourceType"],
                            "state": a["State"]
                        }
                        for a in attachments
                    ]
                },
                "metrics": [],
                "raw": tgw
            })

        return resources