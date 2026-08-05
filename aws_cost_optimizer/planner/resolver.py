"""
CatalogResolver
"""

import fnmatch


class CatalogResolver:
    def __init__(self, catalog: dict):
        self.catalog = catalog

    def resolve(self, service: str, usage_type: str):
        
        for key, item in self.catalog.items():

            # Skip disabled entries
            if item.get("enabled") is False:
                continue

            if service not in item.get("services", []):
                continue
            for pattern in item.get("usage_patterns", []):
                if fnmatch.fnmatch(usage_type, pattern):
                    return {
                        "resource_type": item.get("resource_type", key),
                        "collector": item["collector"],
                        "key": key,
                    }

        return None
