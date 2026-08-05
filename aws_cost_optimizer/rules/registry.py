"""
Rule registry - manages rule registration and lookup.
"""

from typing import Dict, Optional


class RuleRegistry:
    def __init__(self):
        
        self._rules: Dict[str, 'BaseRule'] = {}

    def register(self, rule: 'BaseRule'):
        """Register a rule by its key."""
        self._rules[rule.key] = rule

    def get(self, resource_type: str) -> Optional['BaseRule']:
        """Get rule for a resource type."""
        return self._rules.get(resource_type)

    def get_all(self) -> Dict[str, 'BaseRule']:
        """Get all registered rules."""
        return self._rules


# Global registry instance
registry = RuleRegistry()