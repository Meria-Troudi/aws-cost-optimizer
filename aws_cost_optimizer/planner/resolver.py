import fnmatch


class CatalogResolver:

    def __init__(self, catalog: dict):
        self.catalog = catalog

    def resolve(
        self,
        service: str,
        usage_type: str,
    ):

        enabled_items = [
            (key, item)
            for key, item in self.catalog.items()
            if item.get("rules", {}).get("enabled") is not False
        ]

        for key, item in enabled_items:

            if not self._service_matches(item, service):
                continue

            billing = item.get("billing", {})

            for pattern in billing.get(
                "usage_patterns",
                [],
            ):

                if fnmatch.fnmatch(
                    str(usage_type).lower(),
                    str(pattern).lower(),
                ):
                    return self._result(key, item)

        claimants = [
            (key, item)
            for key, item in enabled_items
            if self._service_matches(item, service)
        ]

        if len(claimants) == 1:

            key, item = claimants[0]

            billing = item.get("billing", {})

            if billing.get("service_fallback") is True:
                return self._result(key, item)

        return None

    @staticmethod
    def _service_matches(
        item: dict,
        service: str,
    ) -> bool:

        billing = item.get("billing", {})

        services = billing.get("services", [])

        return any(
            str(service).strip().lower()
            == str(candidate).strip().lower()
            for candidate in services
        )

    @staticmethod
    def _result(key: str, item: dict) -> dict:

        collector = item.get("collector", {})

        return {
            "resource_type": collector.get(
                "resource_type",
                key,
            ),
            "collector": collector.get(
                "key",
                key,
            ),
            "key": key,
        }
