#!/usr/bin/env python3

"""
SQLAlchemy ORM models for the Krawl honeypot database.
Stores access logs, credential attempts, attack detections, and IP statistics.
"""

from datetime import datetime
from typing import Optional, List, Dict

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from sanitizer import (
    MAX_IP_LENGTH,
    MAX_PATH_LENGTH,
    MAX_USER_AGENT_LENGTH,
    MAX_CREDENTIAL_LENGTH,
    MAX_ATTACK_PATTERN_LENGTH,
    MAX_CITY_LENGTH,
    MAX_ASN_ORG_LENGTH,
    MAX_REPUTATION_SOURCE_LENGTH,
)


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class AccessLog(Base):
    """
    Records all HTTP requests to the honeypot.

    Stores request metadata, suspicious activity flags, and timestamps
    for analysis and dashboard display.
    """

    __tablename__ = "access_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), nullable=False, index=True, ForeignKey('ip_logs.id', ondelete='CASCADE'))
    ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(MAX_PATH_LENGTH), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(MAX_USER_AGENT_LENGTH), nullable=True
    )
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")
    is_suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_honeypot_trigger: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )

    # Relationship to attack detections
    attack_detections: Mapped[List["AttackDetection"]] = relationship(
        "AttackDetection", back_populates="access_log", cascade="all, delete-orphan"
    )

    # Indexes for common queries
    __table_args__ = (
        Index("ix_access_logs_ip_timestamp", "ip", "timestamp"),
        Index("ix_access_logs_is_suspicious", "is_suspicious"),
        Index("ix_access_logs_is_honeypot_trigger", "is_honeypot_trigger"),
    )

    def __repr__(self) -> str:
        return f"<AccessLog(id={self.id}, ip='{self.ip}', path='{self.path[:50]}')>"


class CredentialAttempt(Base):
    """
    Records captured login attempts from honeypot login forms.

    Stores the submitted username and password along with request metadata.
    """

    __tablename__ = "credential_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(MAX_PATH_LENGTH), nullable=False)
    username: Mapped[Optional[str]] = mapped_column(
        String(MAX_CREDENTIAL_LENGTH), nullable=True
    )
    password: Mapped[Optional[str]] = mapped_column(
        String(MAX_CREDENTIAL_LENGTH), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )

    # Composite index for common queries
    __table_args__ = (Index("ix_credential_attempts_ip_timestamp", "ip", "timestamp"),)

    def __repr__(self) -> str:
        return f"<CredentialAttempt(id={self.id}, ip='{self.ip}', username='{self.username}')>"


class AttackDetection(Base):
    """
    Records detected attack patterns in requests.

    Linked to the parent AccessLog record. Multiple attack types can be
    detected in a single request.
    """

    __tablename__ = "attack_detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_log_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("access_logs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attack_type: Mapped[str] = mapped_column(String(50), nullable=False)
    matched_pattern: Mapped[Optional[str]] = mapped_column(
        String(MAX_ATTACK_PATTERN_LENGTH), nullable=True
    )

    # Relationship back to access log
    access_log: Mapped["AccessLog"] = relationship(
        "AccessLog", back_populates="attack_detections"
    )

    def __repr__(self) -> str:
        return f"<AttackDetection(id={self.id}, type='{self.attack_type}')>"


class IpStats(Base):
    """
    Aggregated statistics per IP address.

    Includes fields for future GeoIP and reputation enrichment.
    Updated on each request from an IP.
    """

    __tablename__ = "ip_stats"

    ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), primary_key=True)
    total_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )

    # GeoIP fields (populated by future enrichment)
    country_code: Mapped[Optional[str]] = mapped_column(String(2), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(MAX_CITY_LENGTH), nullable=True)
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    asn: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    asn_org: Mapped[Optional[str]] = mapped_column(
        String(MAX_ASN_ORG_LENGTH), nullable=True
    )
    list_on: Mapped[Optional[Dict[str, str]]] = mapped_column(JSON, nullable=True)

    # Reputation fields (populated by future enrichment)
    reputation_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    reputation_source: Mapped[Optional[str]] = mapped_column(
        String(MAX_REPUTATION_SOURCE_LENGTH), nullable=True
    )
    reputation_updated: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )

    # Analyzed metrics, category and category scores
    analyzed_metrics: Mapped[Dict[str, object]] = mapped_column(JSON, nullable=True)
    category: Mapped[str] = mapped_column(String, nullable=True)
    category_scores: Mapped[Dict[str, int]] = mapped_column(JSON, nullable=True)
    manual_category: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    last_analysis: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<IpStats(ip='{self.ip}', total_requests={self.total_requests})>"


class CategoryHistory(Base):
    """
    Records category changes for IP addresses over time.

    Tracks when an IP's category changes, storing both the previous
    and new category along with timestamp for timeline visualization.
    """

    __tablename__ = "category_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), nullable=False, index=True)
    old_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    new_category: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )

    # Composite index for efficient IP-based timeline queries
    __table_args__ = (Index("ix_category_history_ip_timestamp", "ip", "timestamp"),)

    def __repr__(self) -> str:
        return f"<CategoryHistory(ip='{self.ip}', {self.old_category} -> {self.new_category})>"


# class IpLog(Base):
#     """
#     Records all IPs that have accessed the honeypot, along with aggregated stats and inferred user category.
#     """
#     __tablename__ = 'ip_logs'

#     id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
#     ip: Mapped[str] = mapped_column(String(MAX_IP_LENGTH), nullable=False, index=True)
#     stats: Mapped[List[str]] = mapped_column(String(MAX_PATH_LENGTH))
#     category: Mapped[str] = mapped_column(String(15))
#     manual_category: Mapped[bool] = mapped_column(Boolean, default=False)
#     last_analysis: Mapped[datetime] = mapped_column(DateTime, index=True),

#     # Relationship to attack detections
#     access_logs: Mapped[List["AccessLog"]] = relationship(
#         "AccessLog",
#         back_populates="ip",
#         cascade="all, delete-orphan"
#     )

#     # Indexes for common queries
#     __table_args__ = (
#         Index('ix_access_logs_ip_timestamp', 'ip', 'timestamp'),
#         Index('ix_access_logs_is_suspicious', 'is_suspicious'),
#         Index('ix_access_logs_is_honeypot_trigger', 'is_honeypot_trigger'),
#     )

#     def __repr__(self) -> str:
#         return f"<AccessLog(id={self.id}, ip='{self.ip}', path='{self.path[:50]}')>"
