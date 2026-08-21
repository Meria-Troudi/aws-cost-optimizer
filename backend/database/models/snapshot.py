"""
Resource snapshot model.

"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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


class ResourceSnapshot(Base):
    __tablename__ = "resource_snapshots"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    resource_id: Mapped[int] = mapped_column(
        ForeignKey(
            "resources.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    scan_run_id: Mapped[int] = mapped_column(
        ForeignKey(
            "scan_runs.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    state: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    availability_zone: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    configuration: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    topology: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    relationships: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    raw_response: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    optimization_evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    resource = relationship(
        "Resource",
        back_populates="snapshots",
    )

    scan_run = relationship(
        "ScanRun",
        back_populates="snapshots",
    )