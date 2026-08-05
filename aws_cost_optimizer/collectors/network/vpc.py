from aws.client import get_client


class VPCContextCollector:

    def __init__(self, region):
        self.ec2 = get_client( "ec2", region)
    def collect(self, vpc_id):
        response = self.ec2.describe_vpcs(
            VpcIds=[vpc_id]
        )
        if not response["Vpcs"]:
            return {}
        vpc = response["Vpcs"][0]
        return {
            "vpc_id":vpc["VpcId"],
            "cidr":vpc.get( "CidrBlock" ),
            "state":vpc.get("State"),
            "tags":
                {
                    t["Key"]:
                    t["Value"]
                    for t in vpc.get("Tags",[])
                }

        }