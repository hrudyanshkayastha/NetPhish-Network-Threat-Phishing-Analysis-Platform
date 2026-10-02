"""Unit and integration tests for Investigation Model and Timeline Lifecycle."""

import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.db import Base, Analysis, Detection, IOC, Investigation
from app.investigations.service import (
    create_investigation_dossier,
    generate_investigation_id,
    generate_defensive_recommendations,
)


@pytest.fixture
def db_session():
    """In-memory SQLite test database fixture."""
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(bind=test_engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_create_investigation_dossier_service(db_session):
    """Creates a consolidated investigation in SQLite and checks relationships."""
    # 1. Insert a mock URL analysis
    url_analysis = Analysis(
        analysis_type="URL",
        target="http://203.0.113.50/login/verify",
        status="COMPLETED",
        risk_score=75.0,
        severity="HIGH",
        summary="High-risk phishing indicators",
        details_json={
            "parsed": {"hostname": "203.0.113.50", "registered_domain": ""},
            "features": {"is_ip_host": True},
        },
    )
    db_session.add(url_analysis)
    db_session.flush()

    db_session.add(Detection(
        analysis_id=url_analysis.id,
        detection_type="Raw IP Host Header Lure",
        evidence="Host is 203.0.113.50",
        severity="HIGH",
        confidence="high",
        points=20.0,
    ))
    db_session.add(IOC(
        analysis_id=url_analysis.id,
        value="203.0.113.50",
        canonical_value="203.0.113.50",
        type="IPv4",
        source="URL_ANALYSIS",
        confidence="high",
        classification="Documentation/Test-Net (RFC 5737)",
    ))

    # 2. Insert a mock PCAP analysis
    pcap_analysis = Analysis(
        analysis_type="PCAP",
        target="capture.pcap",
        status="COMPLETED",
        risk_score=50.0,
        severity="MEDIUM",
        summary="Suspicious network activity",
        details_json={
            "file_hash": "abc123hash",
            "packet_count": 20,
            "duration_seconds": 10.0,
            "dns_queries": [],
            "http_events": [],
        },
    )
    db_session.add(pcap_analysis)
    db_session.flush()

    db_session.add(IOC(
        analysis_id=pcap_analysis.id,
        value="203.0.113.50",
        canonical_value="203.0.113.50",
        type="IPv4",
        source="PCAP_FLOW",
        confidence="high",
        classification="Documentation/Test-Net (RFC 5737)",
    ))
    db_session.commit()

    # 3. Create Investigation Dossier
    inv = create_investigation_dossier(
        db=db_session,
        title="Test Incident Dossier",
        analysis_ids=[url_analysis.id, pcap_analysis.id],
        explanation="Preliminary incident triage",
    )

    assert inv.id.startswith("INV-")
    assert inv.title == "Test Incident Dossier"
    assert inv.risk_score > 0
    assert inv.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert len(inv.analyses) == 2
    assert len(inv.detections) >= 1
    assert len(inv.iocs) >= 1
    assert len(inv.correlations) >= 1
    assert len(inv.timeline_events) >= 1
    assert len(inv.recommendations_json) >= 2


def test_defensive_recommendations_generation():
    """Verifies that high-severity investigations yield critical remediation recommendations."""
    recs_critical = generate_defensive_recommendations(
        severity="CRITICAL",
        detections=[{"detection_type": "DNS Query Anomaly"}],
        correlations=[{"correlation_type": "CROSS_SOURCE_IPv4_MATCH"}],
    )
    assert any("Isolate affected internal host" in r for r in recs_critical)
    assert any("Block confirmed malicious destination IPs" in r for r in recs_critical)
    assert any("DNS" in r for r in recs_critical)


def test_generate_investigation_id(db_session):
    """Verifies sequential investigation ID generator format."""
    id1 = generate_investigation_id(db_session)
    assert id1 == "INV-0001"
