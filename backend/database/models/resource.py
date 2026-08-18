"""
Stable AWS resource model.

Resource represents the long-lived identity of an AWS resource.
It is NOT tied to a scan.

Scan-specific state belongs to ResourceSnapshot.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..base import Base


class Resource(Base):
    __tablename__ = "resources"

    __table_args__ = (
        UniqueConstraint(
            "account_id",
            "region",
            "aws_resource_id",
            name="uq_resource_identity",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    account_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    aws_resource_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    service: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    resource_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    region: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
        index=True,
    )

    name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    tags: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    snapshots = relationship(
        "ResourceSnapshot",
        back_populates="resource",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    metrics = relationship(
        "Metric",
        back_populates="resource",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )