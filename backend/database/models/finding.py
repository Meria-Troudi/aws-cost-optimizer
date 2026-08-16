"""
Finding database model.

"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)

from ..base import Base


class Finding(Base):

    __tablename__ = "findings"

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

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    resource_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    finding_key: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
        index=True,
    )

    finding_type: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="optimization",
        index=True,
    )

    # Database finding rows are always raw/resource-level.
    aggregation_scope: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="resource",
        index=True,
    )

    analyzer: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    analyzer_version: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    conditions: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    limitations: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    recommendation_eligible: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="active",
        index=True,
    )
    evidence_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    impact: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    account_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    region: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    observation_period: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="findings",
    )

    recommendations = relationship(
        "Recommendation",
        secondary="recommendation_findings",
        back_populates="findings",
        lazy="selectin",
    )