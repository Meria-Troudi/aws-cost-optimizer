"""
Resource catalog 
"""

import json
from pathlib import Path


class ResourceCatalog:

    def __init__(self):
        catalog_path = Path(__file__).parent / "resource_catalog.json"
        with open(catalog_path) as f:
            self.items = json.load(f)

    def by_key(self, key: str) -> dict:
        item = self.items.get(key)
        return item

    def all(self) -> dict:
        return self.items