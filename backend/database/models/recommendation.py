"""
Recommendation model - final user action.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Float,
    JSON,
    ForeignKey,
    DateTime,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from backend.database.base import Base


class Recommendation(Base):

    __tablename__ = "recommendations"

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False,
        index=True
    )

    title = Column(
        String,
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    action = Column(
        Text,
        nullable=False
    )

    category = Column(
        String,
        nullable=True
    )

    estimated_savings = Column(
        Float,
        nullable=True
    )

    confidence = Column(
        Float,
        nullable=True
    )

    priority = Column(
        String,
        nullable=True  # critical, high, medium, low
    )

    implementation = Column(
        JSON,
        nullable=True
    )

    status = Column(
        String,
        default="open"  # open, in_progress, applied, dismissed
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

    # Relationships
    finding = relationship("Finding", back_populates="recommendations")