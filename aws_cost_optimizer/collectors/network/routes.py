from aws.client import get_client


class RouteTableCollector:
    def __init__(self, region):
        self.ec2 = get_client("ec2",region  )
    def collect_for_subnet(self,subnet_id):
        response = self.ec2.describe_route_tables()
        result=[]
        for table in response["RouteTables"]:
            associations = table.get("Associations",[])
            for assoc in associations:
                if assoc.get( "SubnetId") == subnet_id:
                    routes=[]
                    for route in table.get( "Routes", [] ):
                        routes.append({
                            "destination":route.get("DestinationCidrBlock"),
                            "gateway":route.get("GatewayId"),
                            "nat_gateway":route.get("NatGatewayId" ),
                            "state":route.get( "State")
                        })
                    result.append({"route_table_id": table["RouteTableId"],"routes":routes })
        return result