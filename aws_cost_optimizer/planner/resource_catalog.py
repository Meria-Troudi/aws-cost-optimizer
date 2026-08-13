"""
Resource catalog.

YAML is the source of truth for:
- resource types
- billing mappings
- collectors
"""

from __future__ import annotations

from pathlib import Path    
from typing import Any, Dict

import yaml


class ResourceCatalog:

    def __init__(self) -> None:

        catalog_path = (
            Path(__file__).parent
            / "resource_catalog.yaml"
        )

        if not catalog_path.exists():
            raise FileNotFoundError(
                f"Resource catalog not found: {catalog_path}"
            )

        with open(
            catalog_path,
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError(
                "resource_catalog.yaml must contain a mapping."
            )

        self.items: Dict[str, Dict[str, Any]] = data

    def by_key(self, key: str) -> Dict[str, Any] | None:
        return self.items.get(key)

    def all(self) -> Dict[str, Dict[str, Any]]:
        return self.items


_catalog_instance: ResourceCatalog | None = None


def load_catalog() -> ResourceCatalog:

    global _catalog_instance

    if _catalog_instance is None:
        _catalog_instance = ResourceCatalog()

    return _catalog_instance
