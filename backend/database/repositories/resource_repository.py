"""
Resource persistence.

Resource = stable AWS identity.
ResourceSnapshot = state during one scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

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
    tags: dict[str, str] | None = None,
) -> Resource:

    now = datetime.utcnow()

    resource = (
        db.query(Resource)
        .filter(
            Resource.account_id == account_id,
            Resource.aws_resource_id == aws_resource_id,
            Resource.region == region,
        )
        .one_or_none()
    )

    if resource is None:

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

    resource.last_seen = now

    if service:
        resource.service = service

    if resource_type:
        resource.resource_type = resource_type

    if name:
        resource.name = name

    if tags is not None:
        resource.tags = json_dumps(tags)

    db.flush()

    return resource


def save_resource_snapshot(
    db: Session,
    *,
    resource_id: int,
    scan_run_id: int,
    source_api: str,
    configuration: dict[str, Any] | None = None,
    topology: dict[str, Any] | None = None,
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
        relationships=json_dumps(
            relationships if relationships is not None else {}
        ),
        raw_response=json_dumps(
            raw_response if raw_response is not None else {}
        ),
        optimization_evidence=json_dumps(
            optimization_evidence
            if optimization_evidence is not None
            else {}
        ),
    )

    db.add(snapshot)
    db.flush()

    return snapshot


def get_resource(
    db: Session,
    resource_id: int,
) -> Resource | None:

    return db.get(Resource, resource_id)


def get_resources_for_scan(
    db: Session,
    scan_id: int,
) -> list[Resource]:

    resource_ids = (
        db.query(ResourceSnapshot.resource_id)
        .filter(
            ResourceSnapshot.scan_run_id == scan_id
        )
        .distinct()
        .all()
    )

    ids = [
        row[0]
        for row in resource_ids
        if row[0] is not None
    ]

    if not ids:
        return []

    return (
        db.query(Resource)
        .filter(Resource.id.in_(ids))
        .order_by(Resource.resource_type, Resource.id)
        .all()
    )