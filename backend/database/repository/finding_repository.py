"""
Finding repository - persistence layer for findings.
"""

from sqlalchemy.orm import Session

from backend.database.models.finding import Finding


def save_finding(db: Session, data: dict) -> Finding:
    """Save a finding."""
    finding = Finding(
        scan_run_id=data.get("scan_run_id"),
        resource_id=data.get("resource_id"),
        service=data.get("service"),
        finding_type=data.get("finding_type"),
        title=data.get("title"),
        description=data.get("description"),
        severity=data.get("severity"),
        evidence=data.get("evidence"),
        status=data.get("status", "open"),
    )
    db.add(finding)
    db.flush()
    return finding


def get_findings_by_scan(db: Session, scan_run_id: int):
    """Get all findings for a scan."""
    return (
        db.query(Finding)
        .filter(Finding.scan_run_id == scan_run_id)
        .order_by(Finding.severity.desc())
        .all()
    )


def get_findings_by_resource(db: Session, resource_id: int):
    """Get all findings for a resource."""
    return (
        db.query(Finding)
        .filter(Finding.resource_id == resource_id)
        .all()
    )