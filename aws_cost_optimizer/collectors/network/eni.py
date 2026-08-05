from aws.client import get_client

class ENICollector:
    def __init__(self, region):
        self.ec2 = get_client("ec2",region)
    def collect(self,eni_id):
        response = self.ec2.describe_network_interfaces(
            NetworkInterfaceIds=[eni_id]
        )
        if not response["NetworkInterfaces"]:
            return {}
        eni=response["NetworkInterfaces"][0]
        return {
            "network_interface_id": eni["NetworkInterfaceId"],
            "private_ip":eni.get( "PrivateIpAddress"),
            "subnet_id":eni.get( "SubnetId"),
            "vpc_id":eni.get("VpcId"),
            "description": eni.get( "Description"),
        }