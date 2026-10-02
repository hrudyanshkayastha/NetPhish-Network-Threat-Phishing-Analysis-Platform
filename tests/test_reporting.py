"""Unit tests for JSON and HTML Report Exporters."""

import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.db import Base, Analysis, Detection, IOC, Investigation
from app.investigations.service import create_investigation_dossier
from app.reporting import generate_json_report, generate_html_report


@pytest.fixture
def test_inv():
    """Sets up an investigation with findings for report generation testing."""
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(bind=test_engine)
    session = TestingSession()

    url_rec = Analysis(
        analysis_type="URL",
        target="http://203.0.113.50/banking/login",
        status="COMPLETED",
        risk_score=65.0,
        severity="HIGH",
        summary="High-risk phishing indicators",
        details_json={
            "parsed": {"hostname": "203.0.113.50", "registered_domain": ""},
            "features": {"is_ip_host": True},
        },
    )
    session.add(url_rec)
    session.flush()

    session.add(Detection(
        analysis_id=url_rec.id,
        detection_type="Raw IP Host Header Lure",
        evidence="Target uses raw IP 203.0.113.50",
        severity="HIGH",
        points=20.0,
    ))
    session.add(IOC(
        analysis_id=url_rec.id,
        value="203.0.113.50",
        canonical_value="203.0.113.50",
        type="IPv4",
        source="URL_ANALYSIS",
        confidence="high",
        classification="Documentation/Test-Net (RFC 5737)",
    ))
    session.commit()

    inv = create_investigation_dossier(
        db=session,
        title="Report Generation Test Case",
        analysis_ids=[url_rec.id],
        explanation="Automated test investigation dossier",
    )
    yield session, inv.id
    session.close()


def test_generate_json_report(test_inv):
    """Generates standardized JSON report and validates structure."""
    session, inv_id = test_inv
    report = generate_json_report(session, inv_id)

    assert report["investigation"]["id"] == inv_id
    assert report["report_metadata"]["platform"] == "NETPHISH"
    assert report["report_metadata"]["author"] == "Hrudyansh Kayastha"
    assert "threat_detections" in report
    assert "indicators_of_compromise" in report
    assert "cross_source_correlations" in report
    assert "chronological_timeline" in report


def test_generate_html_report(test_inv):
    """Generates standalone HTML report and checks for required sections and zero forbidden terms."""
    session, inv_id = test_inv
    filepath = generate_html_report(session, inv_id)
    assert Path(filepath).exists()

    with open(filepath, "r", encoding="utf-8") as f:
        html = f.read()

    assert "NETPHISH" in html
    assert inv_id in html
    assert "Forensic Dossier" in html
    assert "Deterministic Threat Detections" in html
    assert "Hrudyansh Kayastha" in html

    # Strict vocabulary verification
    forbidden_terms = [
        "college", "student", "academic", "university",
        "viva", "assignment", "educational project", "beginner project"
    ]
    for term in forbidden_terms:
        assert term not in html.lower(), f"Forbidden word '{term}' found in HTML report!"
