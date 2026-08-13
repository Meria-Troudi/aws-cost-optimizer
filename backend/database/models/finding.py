from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    resource_id: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True,
    )

    finding_type: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
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
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    reason: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    recommendation_eligible: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )

    conditions: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    evidence: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    limitations: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="findings",
    )

    recommendations = relationship(
        "Recommendation",
        back_populates="finding",
        cascade="all, delete-orphan",
    )