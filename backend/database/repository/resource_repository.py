"""
Resource persistence.

Resource is a stable AWS identity (account + region + aws_resource_id).

ResourceSnapshot holds the state of that resource during one scan.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from ..models.resource import Resource
from ..models.snapshot import ResourceSnapshot
from ..utils import json_dumps


def get_or_create_resource(
    db: Session,
    *,
    account_id: str,
    aws_resource_id: str,
    service: str,
    resource_type: str,
    region: str | None,
    name: str | None = None,
    tags: Dict[str, str] | None = None,
) -> Resource:
    """
    Find an existing resource by its stable identity.
    If not found, create it.

    On existing resources, `last_seen` is updated to now.
    """
    now = datetime.utcnow()

    resource = (
        db.query(Resource)
        .filter(
            Resource.account_id == account_id,
            Resource.aws_resource_id == aws_resource_id,
            Resource.region == region,
        )
        .first()
    )

    if resource is not None:
        resource.last_seen = now

        if name:
            resource.name = name

        if tags:
            resource.tags = json_dumps(tags or {})

        db.flush()
        return resource

    resource = Resource(
        account_id=account_id,
        aws_resource_id=aws_resource_id,
        service=service,
        resource_type=resource_type,
        region=region,
        name=name,
        tags=json_dumps(tags or {}),
        first_seen=now,
        last_seen=now,
    )

    db.add(resource)
    db.flush()
    return resource


def save_resource_snapshot(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    source_api: str,
    configuration: Dict[str, Any] | None = None,
    topology: Dict[str, Any] | None = None,
    relationships: Any = None,
    raw_response: Any = None,
    optimization_evidence: Any = None,
    state: str | None = None,
    availability_zone: str | None = None,
) -> ResourceSnapshot:
    snapshot = ResourceSnapshot(
        resource_id=resource_id,
        scan_run_id=scan_run_id,
        source=source_api,
        state=state,
        availability_zone=availability_zone,
        configuration=json_dumps(configuration or {}),
        topology=json_dumps(topology or {}),
        relationships=json_dumps(relationships or {}),
        raw_response=json_dumps(raw_response or {}),
        optimization_evidence=json_dumps(optimization_evidence or {}),
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
    from ..models.snapshot import ResourceSnapshot

    snapshot_resources = (
        db.query(ResourceSnapshot.resource_id)
        .filter(ResourceSnapshot.scan_run_id == scan_id)
        .distinct()
        .all()
    )

    resource_ids = [
        row[0] for row in snapshot_resources if row[0] is not None
    ]

    if not resource_ids:
        return []

    return (
        db.query(Resource)
        .filter(Resource.id.in_(resource_ids))
        .all()
    )
