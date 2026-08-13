"""
Persistence layer for resource collection.
"""
from aws_cost_optimizer.analysis.metrics import (
    count_persistable_metrics,
    metric_has_observed_data,
)
from backend.database.repository.resource_repository import (
    get_or_create_resource,
    save_resource_snapshot,
)
from backend.database.repository.metric_repository import (
    save_metric,
)
class CollectorPersistence:
    def save(self,db,scan,resource: dict,):
        resource_id = resource[ "resource_id"]
        resource_type = resource.get( "resource_type", "unknown", )
        identity = resource.get("identity", {}, )
        state = identity.get( "state" )
        name = identity.get( "name",resource_id,)
        tags = identity.get( "tags", {}, )
        obj = get_or_create_resource(
            db,
            aws_resource_id=resource_id,
            service=self._infer_service(
                resource_type
            ),
            resource_type=resource_type,
            region=resource.get("region"),
            scan_run_id=scan.id,
            name=name,
            tags=tags,
        )
        db.flush()
        configuration = resource.get("configuration",{}, )
        topology = resource.get( "topology", {},)
        relationships = resource.get( "relationships", {},)
        optimization_evidence = resource.get("optimization_evidence")
        if optimization_evidence:
            relationships = {
                **relationships,
                "optimization_evidence": optimization_evidence,
            }
        raw = resource.get("raw",{},)
        if configuration or topology or relationships or raw:
            save_resource_snapshot(
                db,
                resource_id=obj.id,
                scan_run_id=scan.id,
                source_api="collector",
                configuration=configuration,
                raw_response=raw,
                topology=topology,
                relationships=relationships,
                state=state,
                availability_zone=
                    configuration.get(
                        "availability_zone"
                    ),
            )
        self._save_observations( db=db, scan=scan, resource_obj=obj, resource=resource,)
        return obj
    def _save_observations(self,db,scan,resource_obj,resource,):
        observations = resource.get( "observations", {},)
        cloudwatch = observations.get( "cloudwatch")
        if not cloudwatch:
            return
        metrics = cloudwatch.get("metrics",{})
        if isinstance(metrics, dict):
            metric_list = list(metrics.values())
        else:
            metric_list = metrics
        for metric in metric_list:
            if not metric_has_observed_data(metric):
                continue
            save_metric(db, resource_id=resource_obj.id, scan_run_id=scan.id, metric=metric)
    def count_metrics(self,resource: dict,) -> int:
        observations = resource.get("observations",{})
        cloudwatch = observations.get( "cloudwatch" )
        if not cloudwatch:
            return 0
        return count_persistable_metrics(
            cloudwatch.get("metrics", {})
        )
    def _infer_service(self,resource_type: str,) -> str:
        return {
            "nat_gateway":"Amazon Virtual Private Cloud",
            "transit_gateway":"AWS Transit Gateway",
            "vpc_endpoint":"Amazon Virtual Private Cloud",
            "rds_instance":"Amazon Relational Database Service",
            "rds_cluster":"Amazon Relational Database Service",
            "rds_snapshot":"Amazon Relational Database Service",
            "ec2_instance":"Amazon Elastic Compute Cloud - Compute",
            "ebs_volume":"Amazon Elastic Compute Cloud - Compute",
            "elastic_ip":"Amazon Elastic Compute Cloud - Compute",
            "public_ipv4":"Amazon Virtual Private Cloud",
            "load_balancer":"Amazon Elastic Load Balancing",
            "eks_cluster": "Amazon Elastic Container Service for Kubernetes",
        }.get(resource_type,"Unknown",
        )
