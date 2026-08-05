"""
NAT Gateway Collector

"""

from datetime import datetime, timedelta

from aws.client import get_client
from collectors.base import BaseCollector
from collectors.registry import register
from collectors.metric_collector import CloudWatchMetricCollector


@register
class NatGatewayCollector(BaseCollector):

    key = "nat_gateway"

    def collect(self) -> list:
        ec2 = get_client("ec2", self.region)
        cloudwatch = get_client("cloudwatch", self.region)

        print(f"[{self.region}] Collecting NAT Gateways")

        # Discover NAT Gateways
        nat_gateways = self._get_nat_gateways(ec2)
        print(f"[{self.region}] NAT gateways discovered: {len(nat_gateways)} found")

        # Discover supporting resources for dependency analysis
        metric_collector = CloudWatchMetricCollector(cloudwatch)
        route_tables = self._get_route_tables(ec2)
        subnets = self._get_subnets(ec2)
        instances = self._get_instances(ec2)

        # Time period for metrics
        start = datetime.utcnow() - timedelta(days=30)
        end = datetime.utcnow()

        resources = []

        for nat in nat_gateways:
            # Skip non-available NAT Gateways
            if nat["State"] != "available":
                continue

            nat_id = nat["NatGatewayId"]
            subnet_id = nat.get("SubnetId")
            vpc_id = nat.get("VpcId")

            # Find subnet and availability zone
            subnet = self._find_subnet(subnet_id, subnets)
            availability_zone = subnet.get("AvailabilityZone") if subnet else None

            # Analyze dependencies
            dependencies = self._find_dependencies(
                nat_id, route_tables, subnets, instances
            )

            # Dynamically discover and collect CloudWatch metrics
            metrics = metric_collector.collect(
                namespace="AWS/NATGateway",
                dimensions=[{"Name": "NatGatewayId", "Value": nat_id}],
                start=start,
                end=end,
            )

            print(f"  NAT {nat_id}: AZ={availability_zone}, VPC={vpc_id}, Metrics={len(metrics)}")

            resources.append({
                "resource_id": nat_id,
                "resource_type": "nat_gateway",
                "region": self.region,
                "state": nat["State"],
                "name": nat_id,
                "tags": {
                    t["Key"]: t["Value"]
                    for t in nat.get("Tags", [])
                },
                "attributes": {
                    "vpc_id": vpc_id,
                    "subnet_id": subnet_id,
                    "availability_zone": availability_zone,
                    "connectivity_type": nat.get("ConnectivityType"),
                    "availability_mode": nat.get("AvailabilityMode"),
                    "created_time": (
                        nat.get("CreateTime").isoformat()
                        if nat.get("CreateTime")
                        else None
                    ),
                    "has_public_ip": any(
                        addr.get("PublicIp")
                        for addr in nat.get("NatGatewayAddresses", [])
                    ),
                    "network_interfaces": [
                        {
                            "allocation_id": addr.get("AllocationId"),
                            "public_ip": addr.get("PublicIp"),
                            "network_interface_id": addr.get("NetworkInterfaceId"),
                            "private_ip": addr.get("PrivateIp"),
                        }
                        for addr in nat.get("NatGatewayAddresses", [])
                    ],
                    "dependencies": dependencies,
                },
                "metrics": metrics,
                "raw": nat,
            })

        return resources

    # -------------------------------
    # AWS discovery methods
    # -------------------------------

    def _get_nat_gateways(self, ec2):
         
        paginator = ec2.get_paginator("describe_nat_gateways")
        nat_gateways = []
        for page in paginator.paginate():
            nat_gateways.extend(page.get("NatGateways", []))
        return nat_gateways

    def _get_route_tables(self, ec2):
        paginator = ec2.get_paginator("describe_route_tables")
        route_tables = []
        for page in paginator.paginate():
            route_tables.extend(page.get("RouteTables", []))
        return route_tables

    def _get_subnets(self, ec2):
 
        paginator = ec2.get_paginator("describe_subnets")
        subnets = []
        for page in paginator.paginate():
            subnets.extend(page.get("Subnets", []))
        return subnets

    def _get_instances(self, ec2):
        paginator = ec2.get_paginator("describe_instances")
        instances = []
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                instances.extend(reservation.get("Instances", []))
        return instances

    # -------------------------------
    # Dependency analysis
    # -------------------------------

    def _find_dependencies(self, nat_id, route_tables, subnets, instances):
      
        used_route_tables = []
        dependent_subnets = []
        dependent_instances = []
        nat_routes = []

        # Find route tables that reference this NAT Gateway
        for table in route_tables:
            found_nat_route = False
            
            for route in table.get("Routes", []):
                if route.get("NatGatewayId") == nat_id:
                    # Capture route details
                    nat_routes.append({
                        "route_table_id": table["RouteTableId"],
                        "destination": route.get("DestinationCidrBlock"),
                        "state": route.get("State"),
                    })
                    
                    route_id = table["RouteTableId"]
                    used_route_tables.append(route_id)
                    found_nat_route = True
                    break

            # Find subnets associated with this route table
            if found_nat_route:
                for assoc in table.get("Associations", []):
                    subnet_id = assoc.get("SubnetId")
                    if subnet_id:
                        dependent_subnets.append(subnet_id)

        for instance in instances:
            subnet_id = instance.get("SubnetId")
            if subnet_id in dependent_subnets:
                dependent_instances.append(instance.get("InstanceId"))

        return {
            "route_tables": list(set(used_route_tables)),
            "routes": nat_routes,
            "subnets": list(set(dependent_subnets)),
            "resource_count": {
                "subnets": len(set(dependent_subnets)),
                "route_tables": len(set(used_route_tables)),
                "routes": len(nat_routes),
            },
        }

    def _find_subnet(self, subnet_id, subnets):
        """Find subnet by ID."""
        for subnet in subnets:
            if subnet["SubnetId"] == subnet_id:
                return subnet
        return None


 