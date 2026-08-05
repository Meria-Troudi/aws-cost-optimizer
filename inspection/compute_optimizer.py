import boto3
from datetime import datetime


class ComputeOptimizerCollector:

    def __init__(self, region="us-east-1"):
        # create a boto3 client for Compute Optimizer
        self.client = boto3.client("compute-optimizer", region_name=region)

    def get_status(self):
    

        response = self.client.get_enrollment_status()

        return {
            "status": response.get("status"),
            "member_accounts_enrolled": response.get(
                "numberOfMemberAccountsOptedIn"
            )
        }
    def get_summary(self):

        response = self.client.get_recommendation_summaries()

        summary = response.get("recommendationSummaries", [])

        return summary

    def get_ec2_recommendations(self):

        # Manually paginate since get_ec2_instance_recommendations is not pageable via boto3 paginator
        recommendations = []

        next_token = None
        while True:
            params = {}
            if next_token:
                params['nextToken'] = next_token

            resp = self.client.get_ec2_instance_recommendations(**params)

            for item in resp.get('instanceRecommendations', []):
                recommendations.append({
                    "source": "AWS Compute Optimizer",
                    "resource_id": item.get("instanceArn"),
                    "instance_name": item.get("instanceName"),
                    "current_instance_type": item.get("currentInstanceType"),
                    "finding": item.get("finding"),
                    "recommendation_options": item.get("recommendationOptions", []),
                    "lookback_period": item.get("lookBackPeriodInDays"),
                    "generated_at": datetime.utcnow().isoformat()
                })

            next_token = resp.get('nextToken')
            if not next_token:
                break

        return recommendations
collector = ComputeOptimizerCollector(region="us-east-1")
report = {

    "status":
        collector.get_status(),

    "summary":
        collector.get_summary(),

    "ec2":
        collector.get_ec2_recommendations()

}


with open("compute_optimizer_report.json", "w") as f:
    import json
    json.dump(report, f, indent=4)