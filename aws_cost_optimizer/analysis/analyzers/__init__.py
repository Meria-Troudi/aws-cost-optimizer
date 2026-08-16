"""
Analysis analyzers.

Importing this package registers all analyzers.
"""

from .eks import EKSAnalyzer
from .ipv4 import IPv4Analyzer
from .load_balancer import ElbAnalyzer
from .nat_gateway import NatGatewayAnalyzer
from .rds import RDSAnalyzer
from .transit_gateway import TransitGatewayAnalyzer
from .vpc_endpoint import VpcEndpointAnalyzer

__all__ = [
    "NatGatewayAnalyzer",
    "RDSAnalyzer",
    "TransitGatewayAnalyzer",
    "VpcEndpointAnalyzer",
    "IPv4Analyzer",
    "EKSAnalyzer",
    "ElbAnalyzer",
]