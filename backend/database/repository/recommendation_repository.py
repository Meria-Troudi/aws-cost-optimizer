"""
Recommendation repository - persistence layer for recommendations.
"""

from sqlalchemy.orm import Session

from backend.database.models.recommendation import Recommendation


def save_recommendation(db: Session, data: dict) -> Recommendation:
    """Save a recommendation."""
    obj = Recommendation(
        finding_id=data.get("finding_id"),
        title=data.get("title"),
        description=data.get("description"),
        action=data.get("action"),
        category=data.get("category"),
        estimated_savings=data.get("estimated_savings"),
        confidence=data.get("confidence"),
        priority=data.get("priority"),
        implementation=data.get("implementation"),
        status=data.get("status", "open"),
    )
    db.add(obj)
    db.flush()
    return obj


def get_recommendations_by_finding(db: Session, finding_id: int):
    """Get all recommendations for a finding."""
    return (
        db.query(Recommendation)
        .filter(Recommendation.finding_id == finding_id)
        .all()
    )


def get_recommendations_by_scan(db: Session, scan_run_id: int):
    """Get all recommendations for a scan run (via findings)."""
    from backend.database.models.finding import Finding

    return (
        db.query(Recommendation)
        .join(Finding, Recommendation.finding_id == Finding.id)
        .filter(Finding.scan_run_id == scan_run_id)
        .all()
    )