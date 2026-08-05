"""
Rules engine for generating findings from investigations.
"""

from aws_cost_optimizer.rules.engine import RuleEngine
from aws_cost_optimizer.rules.registry import RuleRegistry, registry
from aws_cost_optimizer.rules.nat_gateway import NATGatewayRule

# Register rules
registry.register(NATGatewayRule())

__all__ = ["RuleEngine", "RuleRegistry", "registry"]
