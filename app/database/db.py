"""SQLite database engine, connection pooling, and SQLAlchemy relational models."""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime, Text, JSON, ForeignKey, Table
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

from app.config import DB_PATH

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def utc_now() -> datetime:
    """Returns current UTC timestamp."""
    return datetime.now(timezone.utc)


# Association Table for Many-to-Many relationship between Investigations and Analyses
investigation_analyses = Table(
    "investigation_analyses",
    Base.metadata,
    Column("investigation_id", String(64), ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True),
    Column("analysis_id", Integer, ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True)
)


class Analysis(Base):
    """Core analysis execution record for URL or PCAP ingestion."""
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_type = Column(String(32), nullable=False)  # URL, PCAP
    target = Column(Text, nullable=False)               # URL string or PCAP filename
    status = Column(String(32), default="COMPLETED")    # PENDING, RUNNING, COMPLETED, FAILED
    risk_score = Column(Float, default=0.0)
    severity = Column(String(32), default="LOW")        # LOW, MEDIUM, HIGH, CRITICAL
    summary = Column(Text, nullable=True)
    details_json = Column(JSON, default=dict)           # Full raw parsed features/metadata
    created_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, default=utc_now, nullable=True)

    # Relationships
    flows = relationship("NetworkFlow", back_populates="analysis", cascade="all, delete-orphan")
    detections = relationship("Detection", back_populates="analysis", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="analysis", cascade="all, delete-orphan")
    investigations = relationship("Investigation", secondary=investigation_analyses, back_populates="analyses")


class NetworkFlow(Base):
    """Aggregated 5-tuple logical connection flow."""
    __tablename__ = "network_flows"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    src_ip = Column(String(64), nullable=False)
    dst_ip = Column(String(64), nullable=False)
    src_port = Column(Integer, nullable=False)
    dst_port = Column(Integer, nullable=False)
    protocol = Column(String(16), nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    duration = Column(Float, default=0.0)
    tcp_flags = Column(String(64), default="")

    analysis = relationship("Analysis", back_populates="flows")


class Detection(Base):
    """Deterministic security detection triggered by URL or network heuristics."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True)
    detection_type = Column(String(128), nullable=False)
    source = Column(String(128), nullable=True)
    destination = Column(String(128), nullable=True)
    evidence = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False)       # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(32), default="high")     # low, medium, high
    points = Column(Float, default=0.0)
    created_at = Column(DateTime, default=utc_now)

    analysis = relationship("Analysis", back_populates="detections")
    investigation = relationship("Investigation", back_populates="detections")


class IOC(Base):
    """Normalized Indicator of Compromise with provenance tracking."""
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True)
    value = Column(String(512), nullable=False)
    canonical_value = Column(String(512), nullable=False, index=True)
    type = Column(String(32), nullable=False)           # IPv4, DOMAIN, URL, HASH, EMAIL
    source = Column(String(64), nullable=False)         # URL_ANALYSIS, PCAP_FLOW, DNS_QUERY, HTTP_METADATA
    confidence = Column(String(32), default="medium")   # low, medium, high
    classification = Column(String(64), nullable=True)  # RFC scope / service context
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)

    analysis = relationship("Analysis", back_populates="iocs")
    investigation = relationship("Investigation", back_populates="iocs")


class Correlation(Base):
    """Cross-source and temporal linkages discovered across disparate evidence."""
    __tablename__ = "correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    correlation_type = Column(String(64), nullable=False)
    ioc_value = Column(String(512), nullable=False)
    source_a = Column(String(64), nullable=False)
    source_b = Column(String(64), nullable=False)
    evidence = Column(Text, nullable=False)
    confidence = Column(String(32), default="high")
    points = Column(Float, default=15.0)
    time_delta_seconds = Column(Float, nullable=True)

    investigation = relationship("Investigation", back_populates="correlations")


class Investigation(Base):
    """Consolidated security investigation record unifying multiple analyses."""
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)  # INV-0001
    title = Column(String(255), nullable=False)
    status = Column(String(32), default="OPEN")            # OPEN, IN_REVIEW, CLOSED
    risk_score = Column(Float, default=0.0)
    severity = Column(String(32), default="LOW")           # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=True)
    recommendations_json = Column(JSON, default=list)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    analyses = relationship("Analysis", secondary=investigation_analyses, back_populates="investigations")
    detections = relationship("Detection", back_populates="investigation", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="investigation", cascade="all, delete-orphan")
    correlations = relationship("Correlation", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="investigation", cascade="all, delete-orphan")


class TimelineEvent(Base):
    """Chronological event in the attack/evidence progression timeline."""
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    source = Column(String(128), nullable=True)
    destination = Column(String(128), nullable=True)
    ioc_value = Column(String(512), nullable=True)
    title = Column(String(255), nullable=False)
    details = Column(Text, nullable=True)
    points = Column(Float, default=0.0)

    investigation = relationship("Investigation", back_populates="timeline_events")


class Report(Base):
    """Exported investigation report (JSON or HTML)."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(64), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String(16), nullable=False)  # JSON, HTML
    filename = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="reports")


def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates database schema if tables do not exist."""
    Base.metadata.create_all(bind=engine)
