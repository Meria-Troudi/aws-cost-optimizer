"""
Resource persistence.
"""

from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.orm import Session

from ..models.resource import Resource
from ..models.snapshot import ResourceSnapshot
from ..utils import json_dumps


def save_resource(
    db: Session,
    data: dict,
) -> Resource:
    """Save a new resource."""
    resource = Resource(**data)
    db.add(resource)
    db.flush()
    return resource


def get_or_create_resource(
    db: Session,
    *,
    aws_resource_id: str,
    service: str,
    resource_type: str,
    region: str | None,
    scan_run_id: int,
    name: str | None = None,
    tags: Dict[str, str] | None = None,
) -> Resource:
    resource = (
        db.query(Resource)
        .filter(
            Resource.scan_run_id == scan_run_id,
            Resource.aws_resource_id == aws_resource_id,
        )
        .first()
    )

    if resource is not None:
        return resource

    return save_resource(
        db,
        {
            "scan_run_id": scan_run_id,
            "aws_resource_id": aws_resource_id,
            "service": service,
            "resource_type": resource_type,
            "region": region,
            "name": name,
            "tags": json_dumps(tags or {}),
        },
    )


def save_resource_snapshot(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    source_api: str,
    configuration: Dict[str, Any] | None = None,
    topology: Dict[str, Any] | None = None,
    state: str | None = None,
    raw_response: Any = None,
    relationships: Any = None,
    availability_zone: str | None = None,
) -> ResourceSnapshot:
    """Save a resource snapshot."""
    snapshot = ResourceSnapshot(
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        source=source_api,
        state=state,
        configuration=json_dumps(configuration or {}),
        topology=json_dumps(topology or {}),
    )
    db.add(snapshot)
    db.flush()
    return snapshot


def get_resource(
    db: Session,
    resource_id: int,
):
    return db.get(Resource, resource_id)


def get_resources_for_scan(
    db: Session,
    scan_id: int,
):
    return (
        db.query(Resource)
        .filter(Resource.scan_run_id == scan_id)
        .all()
    )