"""
Cost Explorer API wrapper
"""

from typing import List, Dict, Any

from aws.client import get_client
def _paginate_cost_and_usage(client, params: Dict[str, Any]) -> List[Dict[str, Any]]:

    results_by_period = {}
    response = client.get_cost_and_usage(**params)
    _merge_groups_by_period(results_by_period, response)
    while "NextPageToken" in response and response["NextPageToken"]:
        params["NextPageToken"] = response["NextPageToken"]
        response = client.get_cost_and_usage(**params)
        _merge_groups_by_period(results_by_period, response)
    
    return list(results_by_period.values())


def _merge_groups_by_period(results_by_period: Dict, response: Dict):
    for block in response.get("ResultsByTime", []):
        start = block["TimePeriod"]["Start"]
        if start not in results_by_period:
            results_by_period[start] = {
                "TimePeriod": block["TimePeriod"],
                "Estimated": block.get("Estimated", False),
                "Groups": [],
                "Total": block.get("Total", {}),
            }
        results_by_period[start]["Groups"].extend(block.get("Groups", []))


def get_cost_usage(start: str, end: str, region: str = None) -> List[Dict[str, Any]]:

    client = get_client("ce", "us-east-1")
    params = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
        "GroupBy": [
            {
                "Type": "DIMENSION",
                "Key": "SERVICE",
            },
            {
                "Type": "DIMENSION",
                "Key": "USAGE_TYPE",
            },
        ],
    }
    
    if region:
        params["Filter"] = {
            "Dimensions": {
                "Key": "REGION",
                "Values": [region],
            }
        }
    
    return _paginate_cost_and_usage(client, params)

def get_regions_with_costs(start: str, end: str) -> List[str]:
    client = get_client("ce", "us-east-1")
    params = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
        "GroupBy": [
            {
                "Type": "DIMENSION",
                "Key": "REGION",
            },
        ],
    }
    
    results = _paginate_cost_and_usage(client, params)
    regions = set()
    for result in results:
        for group in result["Groups"]:
            region = group["Keys"][0]
            cost = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if cost > 0:
                regions.add(region)
    
    return list(regions)


def get_monthly_totals(start: str, end: str) -> List[Dict[str, Any]]:
    client = get_client("ce", "us-east-1")
    params = {
        "TimePeriod": {
            "Start": start,
            "End": end,
        },
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
    }
    results = _paginate_cost_and_usage(client, params)
    
    return results
