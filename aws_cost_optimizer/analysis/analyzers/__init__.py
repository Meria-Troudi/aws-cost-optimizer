"""
Analysis analyzers.

Importing this package registers all analyzers via their @register
decorator. Each analyzer lives under <domain>/<subdomain>, mirroring
collection/collectors/ (e.g. network/vpc/nat_gateway.py).
"""

from .network.vpc.public_ipv4 import IPv4Analyzer
from .network.vpc.nat_gateway import NatGatewayAnalyzer
from .network.vpc.vpc_endpoint import VpcEndpointAnalyzer
from .network.vpc.transit_gateway import TransitGatewayAnalyzer
from .load_balancing.load_balancer import ElbAnalyzer
from .compute.eks.cluster import EKSAnalyzer
from .compute.ec2 import EC2Analyzer
from .database.instance import RDSAnalyzer
from .database.dynamodb import DynamoDBAnalyzer
from .analytics.quicksight import QuickSightAnalyzer
from .storage.ebs import EBSAnalyzer
from .security.waf import WAFAnalyzer

__all__ = [
    "NatGatewayAnalyzer",
    "IPv4Analyzer",
    "VpcEndpointAnalyzer",
    "TransitGatewayAnalyzer",
    "ElbAnalyzer",
    "EKSAnalyzer",
    "EC2Analyzer",
    "RDSAnalyzer",
    "DynamoDBAnalyzer",
    "QuickSightAnalyzer",
    "EBSAnalyzer",
    "WAFAnalyzer",
]