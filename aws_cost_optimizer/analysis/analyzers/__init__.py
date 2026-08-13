"""
Analysis analyzers.

Importing this package registers all analyzers.
"""

from .nat_gateway import NatGatewayAnalyzer
from .rds import RDSAnalyzer

__all__ = ["NatGatewayAnalyzer", "RDSAnalyzer"]
