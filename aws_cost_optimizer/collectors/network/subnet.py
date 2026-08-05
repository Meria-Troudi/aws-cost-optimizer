from aws.client import get_client


class SubnetContextCollector:

    def __init__(self, region):

        self.ec2 = get_client("ec2",region )

    def collect(self, subnet_id):
        response = self.ec2.describe_subnets(
            SubnetIds=[subnet_id]
        )
        if not response["Subnets"]:
            return {}
        subnet = response["Subnets"][0]
        return {

            "subnet_id":subnet["SubnetId"],
            "vpc_id": subnet["VpcId"],
            "availability_zone": subnet["AvailabilityZone"],
            "cidr": subnet["CidrBlock"],
            "available_ips": subnet["AvailableIpAddressCount"],
            "tags":
                {
                    t["Key"]:
                    t["Value"]

                    for t in subnet.get(
                        "Tags",
                        []
                    )
                }
        }