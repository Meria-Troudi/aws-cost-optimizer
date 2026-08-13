from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey("scan_runs.id"),
        nullable=False,
        index=True,
    )

    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id"),
        nullable=True,
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String,
        nullable=False,
    )

    explanation: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
    )

    priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="requires_validation",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="recommendations",
    )

    finding = relationship(
        "Finding",
        back_populates="recommendations",
    )