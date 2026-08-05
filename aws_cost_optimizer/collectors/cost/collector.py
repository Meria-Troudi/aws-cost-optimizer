"""
Cost collector
"""
from typing import Dict, Any

from collectors.cost.cost_explorer import (
    get_cost_usage,
    get_regions_with_costs,
    get_monthly_totals,
)
from backend.database.models.cost_record import CostRecord


class CostCollector:
    def collect(
        self,
        db,
        scan
    ) -> Dict[str, Any]:

        start = scan.start_date.isoformat()
        end = scan.end_date.isoformat()

        if scan.region:
            regions = [scan.region]
            print(f"  Collecting costs for region: {scan.region}")
        else:
            print("  Discovering regions with costs...")
            regions = get_regions_with_costs(start, end)
            print(f"  Found {len(regions)} regions with costs")

        saved_count = 0
        collected_total = 0.0

        for region in regions:
            results = get_cost_usage(start, end, region=region)

            for result in results:
                from datetime import date
                time_start = date.fromisoformat(result["TimePeriod"]["Start"])
                time_end = date.fromisoformat(result["TimePeriod"]["End"])

                for group in result["Groups"]:
                    keys = group["Keys"]
                    service_name = keys[0]
                    usage_type_name = keys[1]

                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])

                    if amount == 0:
                        continue

                    collected_total += amount

                    record = CostRecord(
                        scan_run_id=scan.id,
                        service=service_name,
                        usage_type=usage_type_name,
                        region=region,
                        amount=amount,
                        start_date=time_start,
                        end_date=time_end,
                    )
                    db.add(record)
                    saved_count += 1

        db.commit()
        print(f"  Saved {saved_count} cost records")

        print("\n  Validating collection...")
        validation = self._validate(start, end, collected_total)

        return validation

    def _validate(self, start: str, end: str, collected_total: float) -> Dict[str, Any]:
        monthly_results = get_monthly_totals(start, end)

        monthly_total = 0.0
        for result in monthly_results:
            if "Total" in result and "UnblendedCost" in result["Total"]:
                monthly_total += float(result["Total"]["UnblendedCost"]["Amount"])

        diff = abs(collected_total - monthly_total)
        matches = diff < 0.01
        print(f"    Collected total:  ${collected_total:.2f}")
        print(f"    Monthly total:    ${monthly_total:.2f}")
        print(f"    Difference:       ${diff:.2f}")
        print(f"    Match:            {'✓' if matches else '✗'}")
        return {
            "collected_total": collected_total,
            "monthly_total": monthly_total,
            "difference": diff,
            "matches": matches,
        }
