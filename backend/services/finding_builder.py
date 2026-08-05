"""
FindingBuilder
"""

from sqlalchemy.orm import Session

from backend.database.models.resource import Resource
from backend.database.models.snapshot import ResourceSnapshot
from backend.database.models.metric import Metric
from backend.database.models.collection_plan import CollectionPlan


class EvaluationContext:
    def __init__(
        self,
        scan_run_id: int,
        service: str,
        region: str,
        usage_type: str,
        resource_type: str,
        cost: float,
        resources: list,
        evidence: dict,
        cost_threshold: float = 100.0,
    ):
        self.scan_run_id = scan_run_id
        self.service = service
        self.region = region
        self.usage_type = usage_type
        self.resource_type = resource_type
        self.cost = cost
        self.resources = resources
        self.evidence = evidence
        self.cost_threshold = cost_threshold


class FindingBuilder:
    def build(self, db: Session, scan):
        print("\n=== Finding Builder ===")
        print(f"Scan ID: {scan.id}")

        scan_run_id = scan.id

        plans = (
            db.query(CollectionPlan)
            .filter(CollectionPlan.scan_run_id == scan_run_id)
            .order_by(CollectionPlan.cost_context.desc())
            .all()
        )

        print(f"Collection plans: {len(plans)}")

        contexts = []

        for plan in plans:
            print(
                f"\nPlan: {plan.collector_name} in {plan.region} - "
                f"{plan.usage_type} (${plan.cost_context:.2f})"
            )

            try:
                resources = (
                    db.query(Resource)
                    .filter(
                        Resource.resource_type == plan.resource_type,
                        Resource.region == plan.region,
                        Resource.scan_run_id == scan_run_id,
                    )
                    .all()
                )
                print(f"  Found {len(resources)} resources")

                resource_objects = []
                for resource in resources:
                    snapshot = (
                        db.query(ResourceSnapshot)
                        .filter(
                            ResourceSnapshot.resource_id == resource.id,
                            ResourceSnapshot.scan_run_id == scan_run_id,
                        )
                        .first()
                    )

                    metrics = (
                        db.query(Metric)
                        .filter(
                            Metric.resource_id == resource.id,
                            Metric.scan_run_id == scan_run_id,
                        )
                        .all()
                    )

                    metric_dict = {}
                    for metric in metrics:
                        metric_dict[metric.metric_name] = {
                            "value": metric.value,
                            "unit": metric.unit,
                            "statistic": metric.statistic,
                        }

                    resource_objects.append(
                        {
                            "resource_id": resource.aws_resource_id,
                            "resource_type": resource.resource_type,
                            "name": resource.name,
                            "region": resource.region,
                            "state": resource.state,
                            "configuration": (
                                snapshot.configuration if snapshot else {}
                            ),
                            "attributes": resource.attributes or {},
                            "metrics": metric_dict,
                        }
                    )

                # Build evidence
                evidence = {
                    "source": "cost_explorer",
                    "service": plan.service,
                    "region": plan.region,
                    "usage_type": plan.usage_type,
                    "dimension_cost": plan.cost_context,
                    "resource_count": len(resource_objects),
                    "resources": resource_objects,
                }

                context = EvaluationContext(
                    scan_run_id=scan_run_id,
                    service=plan.service,
                    region=plan.region,
                    usage_type=plan.usage_type,
                    resource_type=plan.resource_type,
                    cost=plan.cost_context,
                    resources=resource_objects,
                    evidence=evidence,
                    cost_threshold=scan.cost_threshold,
                )

                contexts.append(context)

            except Exception as e:
                print(f"  ERROR building context: {e}")
                continue

        print(f"\n=== Summary ===")
        print(f"Evaluation contexts created: {len(contexts)}")

        return contexts
