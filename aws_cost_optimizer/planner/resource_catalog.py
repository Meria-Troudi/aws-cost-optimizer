"""
Resource catalog.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import yaml


class ResourceCatalog:

    def __init__(self) -> None:

        catalog_path = Path(__file__).parent / "resource_catalog.yaml"

        if not catalog_path.exists():
            raise FileNotFoundError(f"Resource catalog not found: {catalog_path}")

        with open(
            catalog_path,
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError("resource_catalog.yaml must contain a mapping.")
        self.items: Dict[str, Dict[str, Any]] = data

    def all(self) -> Dict[str, Dict[str, Any]]:
        return self.items

    def group_for(self, resource_type: str) -> Dict[str, Any]:
        entry = self.items.get(str(resource_type or "").strip()) or {}
        return {
            "domain": entry.get("domain") or "other",
            "subdomain": entry.get("subdomain"),
            "service": entry.get("service"),
        }


_catalog: ResourceCatalog | None = None


def get_resource_catalog() -> ResourceCatalog:
    global _catalog
    if _catalog is None:
        _catalog = ResourceCatalog()
    return _catalog
