"""
Collector registry
"""

import importlib
from aws_cost_optimizer.planner.resource_catalog import ResourceCatalog

COLLECTORS = {}
def register(cls):
    COLLECTORS[cls.key] = cls
    return cls
def load_collectors():
    
    catalog = ResourceCatalog()
    for key, item in catalog.items.items():
        # Skip disabled entries
        if item.get("enabled") is False:
            continue
        collector_name = item["collector"]
        try:
            importlib.import_module(f"collectors.services.{collector_name}")
        except ImportError:
            pass  

def get_collector(name: str):
    return COLLECTORS.get(name)