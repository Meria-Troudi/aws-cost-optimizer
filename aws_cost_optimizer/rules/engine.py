"""
Rule Engine
"""

from aws_cost_optimizer.rules.registry import registry
from backend.database.repository.finding_repository import save_finding
from backend.database.repository.recommendation_repository import save_recommendation


class RuleEngine:
    def __init__(self, rule_registry=None):
        self.registry = rule_registry or registry

    def run(self, db, contexts):
        created = []

        for context in contexts:
            rule = self.registry.get(context.resource_type)

            if not rule:
                continue

            # Pass context to rule - rule returns list of finding+recommendation dicts
            results = rule.evaluate(context)

            for result in results:
                # Create finding
                finding_data = {
                    "scan_run_id": context.scan_run_id,
                    "resource_id": None,
                    "service": context.service,
                    "finding_type": result.get("finding_type"),
                    "title": result.get("title"),
                    "description": result.get("description"),
                    "severity": result.get("severity"),
                    "evidence": result.get("evidence"),
                    "status": "open",
                }
                finding = save_finding(db, finding_data)
                created.append(finding)

                # Create recommendation if provided
                if result.get("recommendation"):
                    rec_data = result["recommendation"]
                    rec_data["finding_id"] = finding.id
                    save_recommendation(db, rec_data)

        db.commit()
        return created