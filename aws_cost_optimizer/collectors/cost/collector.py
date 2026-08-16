#/aws_cost_optimizer/collectors/cost/collector.py

from __future__ import annotations

from datetime import date
from typing import Any

from backend.database.models.cost_record import CostRecord
from collectors.cost.cost_explorer import (
    get_cost_usage,
    get_monthly_totals,
    get_regions_with_costs,
)
from aws_cost_optimizer.collectors.cost.periods import (
    breakdown_from_ce_monthly,
    month_keys_in_period,
)


class CostCollector:

    def collect(
        self,
        db,
        scan,
    ) -> dict[str, Any]:

        start = scan.start_date.isoformat()
        end = scan.end_date.isoformat()

        if scan.region:
            regions = [scan.region]

            print(
                f"  Collecting costs for region: "
                f"{scan.region}"
            )
        else:
            regions = get_regions_with_costs(
                start,
                end,
            )

            print(
                f"  Found {len(regions)} regions with costs"
            )

        saved_count = 0
        collected_total = 0.0

        for region in regions:

            results = get_cost_usage(
                start,
                end,
                region=region,
            )

            for result in results:

                time_start = date.fromisoformat(
                    result["TimePeriod"]["Start"]
                )

                time_end = date.fromisoformat(
                    result["TimePeriod"]["End"]
                )

                for group in result.get("Groups", []):

                    keys = group.get("Keys", [])

                    if len(keys) < 2:
                        continue

                    service_name = keys[0]
                    usage_type_name = keys[1]

                    # If OPERATION is requested, it will be the third key.
                    operation_name = (
                        keys[2]
                        if len(keys) >= 3 and keys[2]
                        else None
                    )

                    metrics = group.get("Metrics", {})

                    cost_metric = metrics.get(
                        "UnblendedCost",
                        {},
                    )

                    amount = float(
                        cost_metric.get(
                            "Amount",
                            0.0,
                        )
                    )

                    if amount == 0:
                        continue

                    usage_metric = metrics.get(
                        "UsageQuantity",
                        {},
                    )

                    usage_quantity = None
                    if usage_metric.get("Amount") is not None:
                        try:
                            usage_quantity = float(
                                usage_metric["Amount"]
                            )
                        except (TypeError, ValueError):
                            usage_quantity = None

                    unit = usage_metric.get("Unit")

                    collected_total += amount

                    record = CostRecord(
                        scan_run_id=scan.id,
                        service=service_name,
                        usage_type=usage_type_name,
                        operation=operation_name,
                        region=region,
                        amount=amount,
                        usage_quantity=usage_quantity,
                        unit=unit,
                        start_date=time_start,
                        end_date=time_end,
                    )

                    db.add(record)

                    saved_count += 1

        db.commit()

        validation = self._validate(
            start,
            end,
            collected_total,
            scan.region,
            scan_start=scan.start_date,
            scan_end=scan.end_date,
        )

        validation["saved_count"] = saved_count

        return validation

    def _validate(
        self,
        start: str,
        end: str,
        collected_total: float,
        region: str | None = None,
        *,
        scan_start: date | None = None,
        scan_end: date | None = None,
    ) -> dict[str, Any]:

        monthly_results = get_monthly_totals(
            start,
            end,
            region=region,
        )

        monthly_total = 0.0
        monthly_breakdown = breakdown_from_ce_monthly(monthly_results)

        for row in monthly_breakdown:
            monthly_total += float(row["cost"])

        account_breakdown: list[dict[str, float | str]] = []
        if region:
            account_breakdown = breakdown_from_ce_monthly(
                get_monthly_totals(start, end, region=None)
            )

        difference = abs(
            collected_total - monthly_total
        )

        matches = difference < 0.01

        months_included = (
            month_keys_in_period(scan_start, scan_end)
            if scan_start and scan_end
            else [row["month"] for row in monthly_breakdown]
        )

        print(
            f"    Collected total:  "
            f"${collected_total:.2f}"
        )

        print(
            f"    Monthly sum:      "
            f"${monthly_total:.2f}"
        )

        if region:
            print(f"    Billing scope:    {region}")
        else:
            print("    Billing scope:    all regions")

        for row in monthly_breakdown:
            print(
                f"      {row['month']}: "
                f"${float(row['cost']):,.2f}"
            )

        print(
            f"    Difference:       "
            f"${difference:.2f}"
        )

        print(
            f"    Match:            "
            f"{'✓' if matches else '✗'}"
        )

        return {
            "collected_total": collected_total,
            "monthly_total": monthly_total,
            "difference": difference,
            "matches": matches,
            "monthly_breakdown": monthly_breakdown,
            "account_monthly_breakdown": account_breakdown,
            "months_included": months_included,
            "billing_scope": region or "all regions",
        }