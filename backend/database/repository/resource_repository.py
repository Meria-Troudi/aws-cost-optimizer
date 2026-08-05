"""
Resource repository

"""

from sqlalchemy.orm import Session
from datetime import datetime
from decimal import Decimal

from backend.database.models.resource import Resource
from backend.database.models.snapshot import ResourceSnapshot
from backend.database.models.metric import Metric


def _serialize_for_json(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: _serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_for_json(item) for item in obj]
    return obj


def get_or_create_resource(
    db: Session,
    aws_resource_id: str,
    service: str,
    resource_type: str,
    region: str,
    scan_run_id: int = None,
    account_id: str = None,
    state: str = None,
    name: str = None,
    tags: dict = None,
    attributes: dict = None,
) -> Resource:

    resource = (
        db.query(Resource)
        .filter_by(
            aws_resource_id=aws_resource_id,
            account_id=account_id,
        )
        .first()
    )
    
    if resource:
        # Update existing resource with latest state and scan run
        resource.state = state
        resource.name = name
        resource.tags = tags
        resource.attributes = attributes
        resource.scan_run_id = scan_run_id
        return resource
    
    resource = Resource(
        aws_resource_id=aws_resource_id,
        service=service,
        resource_type=resource_type,
        region=region,
        scan_run_id=scan_run_id,
        account_id=account_id,
        state=state,
        name=name,
        tags=tags,
        attributes=attributes,
    )
    db.add(resource)
    db.flush()
    return resource


def save_resource_snapshot(
    db: Session,
    resource_id: int,
    scan_run_id: int,
    source_api: str,
    configuration: dict,
    raw_response: dict,
) -> ResourceSnapshot:
    
    serialized_config = _serialize_for_json(configuration) if configuration else None
    serialized_raw = _serialize_for_json(raw_response) if raw_response else None
    
    snapshot = ResourceSnapshot(
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        source_api=source_api,
        configuration=serialized_config,
        raw_response=serialized_raw,
        collected_at=datetime.utcnow(),
    )
    db.add(snapshot)
    return snapshot


def save_metric(
    db: Session,
    resource_id: int,
    scan_run_id: int,
    namespace: str,
    metric_name: str,
    statistic: str,
    value: float,
    metric_start: datetime,
    metric_end: datetime,
    unit: str = None,
    period: int = None,
    dimensions: dict = None,
    raw_datapoints: list = None,
) -> Metric:
    # Check if metric already exists (deduplication)
    existing = (
        db.query(Metric)
        .filter(
            Metric.resource_id == resource_id,
            Metric.scan_run_id == scan_run_id,
            Metric.metric_name == metric_name,
            Metric.statistic == statistic,
        )
        .first()
    )
    
    if existing:
        # Update existing metric
        existing.value = value
        existing.unit = unit
        existing.metric_start = metric_start
        existing.metric_end = metric_end
        existing.namespace = namespace
        return existing
    
    serialized_datapoints = None
    if raw_datapoints:
        serialized_datapoints = _serialize_for_json(raw_datapoints)
    
    metric = Metric(
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        namespace=namespace,
        metric_name=metric_name,
        statistic=statistic,
        value=value,
        unit=unit,
        metric_start=metric_start,
        metric_end=metric_end,
        period=period,
        dimensions=dimensions,
        raw_datapoints=serialized_datapoints,
    )
    db.add(metric)
    return metric


