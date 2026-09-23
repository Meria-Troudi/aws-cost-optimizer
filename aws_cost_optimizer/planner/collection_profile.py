"""
Collection profile loader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class CollectionProfile:

    REQUIRED_SECTIONS = {
        "identity",
        "configuration",
        "relationships",
        "observations",
        "topology",
    }

    ALIASES = {
        "elastic_ip": "public_ipv4",
        "quicksight_asset": "quicksight",
    }

    def __init__(self) -> None:

        dir_path = Path(__file__).parent / "collection_profiles"

        if not dir_path.is_dir():
            raise FileNotFoundError(
                f"Collection profiles directory not found: {dir_path}"
            )

        profiles: dict[str, dict[str, Any]] = {}

        for yaml_path in sorted(dir_path.glob("*.yaml")):
            with open(yaml_path, "r", encoding="utf-8") as file:
                data = yaml.safe_load(file)

            if not isinstance(data, dict):
                raise ValueError(f"{yaml_path.name} must contain a mapping")

            for resource_type in data:
                if resource_type in profiles:
                    raise ValueError(
                        f"Duplicate resource type '{resource_type}' in "
                        f"{yaml_path.name} (already defined in another "
                        f"collection profile file)"
                    )

            profiles.update(data)

        self.profiles: dict[str, dict[str, Any]] = profiles

        self._validate()

    def _validate(self) -> None:
        for resource_type, profile in self.profiles.items():
            if not isinstance(profile, dict):
                raise ValueError(f"Invalid profile for '{resource_type}'")

            for section in self.REQUIRED_SECTIONS:

                if section not in profile:
                    raise ValueError(f"{resource_type}.{section} is required")

                value = profile[section]

                if not isinstance(value, dict):
                    raise ValueError(f"{resource_type}.{section} " f"must be a mapping")

                if "enabled" in value and not isinstance(
                    value["enabled"],
                    bool,
                ):
                    raise ValueError(
                        f"{resource_type}.{section}.enabled " f"must be boolean"
                    )

    def get(self, resource_type: str) -> dict[str, Any]:

        resource_type = self.ALIASES.get(
            resource_type,
            resource_type,
        )

        return self.profiles.get(
            resource_type,
            {},
        )
