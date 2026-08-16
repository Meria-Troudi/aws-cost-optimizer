import fnmatch


class CatalogResolver:

    def __init__(self, catalog: dict):
        self.catalog = catalog

    def resolve(
        self,
        service: str,
        usage_type: str,
    ):
        
        for key, item in self.catalog.items():

            rules_config = item.get(
                "rules",
                {},
            )

            if rules_config.get(
                "enabled"
            ) is False:
                continue

            billing = item.get(
                "billing",
                {},
            )

            services = billing.get(
                "services",
                [],
            )

            service_match = any(
                str(service).strip().lower()
                == str(candidate).strip().lower()
                for candidate in services
            )

            if not service_match:
                continue

            for pattern in billing.get(
                "usage_patterns",
                [],
            ):

                if fnmatch.fnmatch(
                    str(usage_type).lower(),
                    str(pattern).lower(),
                ):
                    collector = item.get("collector", {},)
                    return {
                        "resource_type":collector.get("resource_type",key,),
                        "collector":collector.get("key",key,),
                        "key":key,
                    }
        return None