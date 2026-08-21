from datetime import date, datetime

from sqlalchemy import (
    Date,
    DateTime,
    Float,
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


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    account_id: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    start_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    end_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
    )

    region: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    cost_threshold: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    progress_percent: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="pending",
        nullable=False,
        index=True,
    )

    outcome: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    cost_validation_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    collection_plans = relationship(
        "CollectionPlan",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    cost_records = relationship(
        "CostRecord",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    snapshots = relationship(
        "ResourceSnapshot",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    findings = relationship(
        "Finding",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )

    recommendations = relationship(
        "Recommendation",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    