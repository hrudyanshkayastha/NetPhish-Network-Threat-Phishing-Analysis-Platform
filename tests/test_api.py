"""Integration tests for FastAPI endpoints using TestClient."""

import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.config import SAMPLES_DIR

client = TestClient(app)


def test_api_health_endpoint():
    """Checks /api/health endpoint status and operational modules."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app_name"] == "NETPHISH"
    assert data["author"] == "Hrudyansh Kayastha"
    assert data["modules"]["url_analyzer"] == "operational"


def test_api_stats_endpoint():
    """Checks /api/stats endpoint platform counters."""
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_analyses" in data
    assert "total_iocs" in data
    assert "active_investigations" in data


def test_api_analyze_clean_url():
    """Sends benign URL to /api/url/analyze."""
    response = client.post("/api/url/analyze", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "https://www.google.com"
    assert data["severity"] == "LOW"
    assert data["risk_score"] < 30.0


def test_api_analyze_suspicious_url():
    """Sends phishing URL to /api/url/analyze."""
    response = client.post("/api/url/analyze", json={"url": "http://203.0.113.50/login/verify"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 35.0
    assert len(data["detections"]) > 0
    assert len(data["iocs"]) > 0


def test_api_analyze_empty_url():
    """Checks validation on empty URL."""
    response = client.post("/api/url/analyze", json={"url": ""})
    assert response.status_code == 422  # Pydantic min_length validation


def test_api_pcap_upload_invalid_extension():
    """Checks rejection of unsupported file types."""
    files = {"file": ("test.txt", b"plain text content", "text/plain")}
    response = client.post("/api/pcap/analyze", files=files)
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]


def test_api_pcap_upload_valid_file():
    """Uploads real synthetic PCAP capture to /api/pcap/analyze."""
    clean_pcap = SAMPLES_DIR / "sample_clean.pcap"
    with open(clean_pcap, "rb") as f:
        files = {"file": ("sample_clean.pcap", f.read(), "application/vnd.tcpdump.pcap")}
    response = client.post("/api/pcap/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["packet_count"] >= 5
    assert data["flow_count"] >= 1
    assert data["severity"] == "LOW"


def test_api_investigation_lifecycle():
    """Tests end-to-end investigation creation, retrieval, and reporting."""
    # 1. Analyze a URL
    url_res = client.post("/api/url/analyze", json={"url": "http://203.0.113.50/login/verify"}).json()
    url_id = url_res["id"]

    # 2. Ingest suspicious PCAP sample
    susp_pcap = SAMPLES_DIR / "sample_suspicious.pcap"
    with open(susp_pcap, "rb") as f:
        files = {"file": ("sample_suspicious.pcap", f.read(), "application/vnd.tcpdump.pcap")}
    pcap_res = client.post("/api/pcap/analyze", files=files).json()
    pcap_id = pcap_res["id"]

    # 3. Create Investigation
    inv_res = client.post("/api/investigations", json={
        "title": "API Correlation Demonstration",
        "analysis_ids": [url_id, pcap_id],
        "explanation": "Demonstrating cross-source IOC correlation via API",
    })
    assert inv_res.status_code == 200
    inv_data = inv_res.json()
    inv_id = inv_data["id"]
    assert inv_id.startswith("INV-")

    # 4. Retrieve Investigation Details
    det_res = client.get(f"/api/investigations/{inv_id}")
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert len(det_data["detections"]) > 0
    assert len(det_data["iocs"]) > 0
    assert len(det_data["timeline"]) > 0
    assert len(det_data["recommendations"]) > 0

    # 5. Query Global IOCs
    iocs_res = client.get("/api/iocs")
    assert iocs_res.status_code == 200
    assert len(iocs_res.json()) > 0

    # 6. Download HTML and JSON Reports
    html_res = client.get(f"/api/reports/{inv_id}/html")
    assert html_res.status_code == 200
    assert "NETPHISH" in html_res.text

    json_res = client.get(f"/api/reports/{inv_id}/json")
    assert json_res.status_code == 200
    assert json_res.json()["investigation"]["id"] == inv_id


def test_api_samples_list():
    """Checks /api/samples endpoint."""
    response = client.get("/api/samples")
    assert response.status_code == 200
    data = response.json()
    assert "pcap_samples" in data
    assert "url_samples" in data
