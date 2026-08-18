"""
Recommendation database model.


"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from ..base import Base


recommendation_findings = Table(
    "recommendation_findings",
    Base.metadata,

    Column(
        "recommendation_id",
        ForeignKey(
            "recommendations.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),

    Column(
        "finding_id",
        ForeignKey(
            "findings.id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
)


class Recommendation(Base):

    __tablename__ = "recommendations"

    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "recommendation_key",
            "recommendation_variant",
            "resource_type",
            "scope",
            name="uq_recommendation_group",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey(
            "scan_runs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    # Primary source finding.
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    recommendation_key: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True,
    )

    recommendation_variant: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="",
        index=True,
    )

    recommendation_scope: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="region",
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    scope: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="cost_optimization",
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )

    action: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    affected_resources: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    limitations: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    financial_impact: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="requires_validation",
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="recommendations",
    )

    primary_finding = relationship(
        "Finding",
        foreign_keys=[finding_id],
        lazy="joined",
    )

    findings = relationship(
        "Finding",
        secondary=recommendation_findings,
        back_populates="recommendations",
        lazy="selectin",
    )