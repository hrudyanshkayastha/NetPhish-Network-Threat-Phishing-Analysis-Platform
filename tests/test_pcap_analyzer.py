"""Unit tests for Scapy PCAP Capture Parsing and Flow Aggregation."""

import pytest
from pathlib import Path
from app.pcap_analysis.analyzer import analyze_pcap_file
from app.config import SAMPLES_DIR


def test_clean_pcap_parsing():
    """Ingests benign clean PCAP and verifies packet count and zero critical findings."""
    clean_path = SAMPLES_DIR / "sample_clean.pcap"
    res = analyze_pcap_file(str(clean_path))

    assert res["packet_count"] >= 5
    assert res["flow_count"] >= 1
    assert res["severity"] == "LOW"
    assert "DNS" in res["protocols"] or "TCP" in res["protocols"]


def test_port_scan_detection_in_pcap():
    """Ingests sample_scan.pcap and verifies port scan heuristic detection."""
    scan_path = SAMPLES_DIR / "sample_scan.pcap"
    res = analyze_pcap_file(str(scan_path))

    scan_detections = [d for d in res["detections"] if d["detection_type"] == "Possible Port Scan"]
    assert len(scan_detections) > 0
    assert "probed" in scan_detections[0]["evidence"]
    assert res["risk_score"] >= 20.0


def test_beaconing_detection_in_pcap():
    """Ingests sample_beacon.pcap and verifies periodic C2 pattern detection."""
    beacon_path = SAMPLES_DIR / "sample_beacon.pcap"
    res = analyze_pcap_file(str(beacon_path))

    beacon_detections = [d for d in res["detections"] if d["detection_type"] == "Possible Beaconing Pattern"]
    assert len(beacon_detections) > 0
    assert "variance coeff" in beacon_detections[0]["evidence"]


def test_dns_anomaly_detection_in_pcap():
    """Ingests sample_dns_anomaly.pcap and verifies long query/depth detection."""
    dns_path = SAMPLES_DIR / "sample_dns_anomaly.pcap"
    res = analyze_pcap_file(str(dns_path))

    dns_detections = [d for d in res["detections"] if "DNS" in d["detection_type"]]
    assert len(dns_detections) > 0
    assert any("Anomalous query string" in d["evidence"] for d in dns_detections)


def test_http_metadata_extraction_in_pcap():
    """Ingests sample_suspicious.pcap and verifies HTTP Host and URI extraction."""
    susp_path = SAMPLES_DIR / "sample_suspicious.pcap"
    res = analyze_pcap_file(str(susp_path))

    assert len(res["http_events"]) > 0
    http_evt = res["http_events"][0]
    assert http_evt["host"] == "203.0.113.50"
    assert "/login/verify" in http_evt["uri"]

    # Also checks raw IP host header detection
    assert any("HTTP Direct IP Host Header" == d["detection_type"] for d in res["detections"])


def test_malformed_pcap_exception_handling():
    """Verifies that corrupted capture files raise ValueError gracefully without crashing."""
    malformed_path = SAMPLES_DIR / "sample_malformed.pcap"
    with pytest.raises(ValueError):
        analyze_pcap_file(str(malformed_path))
