"""Unit tests for standalone Network and Anomaly Heuristic Rules."""

import pytest
from datetime import datetime, timezone, timedelta

from app.pcap_analysis.detector import (
    detect_port_scans,
    detect_high_connection_rate,
    detect_beaconing,
    detect_unusual_ports,
    detect_icmp_burst,
    detect_http_metadata_anomalies,
)


def test_detect_port_scans_logic():
    """Triggers port scan rule when >= 10 unique destination ports are contacted."""
    pkts = []
    base_time = datetime.now(timezone.utc)
    for port in range(1, 15):
        pkts.append({
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + port,
            "dst_port": port,
            "protocol": "TCP",
            "timestamp": base_time + timedelta(seconds=port * 0.1),
        })

    detections = detect_port_scans(pkts)
    assert len(detections) == 1
    assert detections[0]["detection_type"] == "Possible Port Scan"
    assert "10.0.0.5" in detections[0]["evidence"]


def test_detect_high_connection_rate_logic():
    """Triggers high connection rate when >= 50 packets occur within 10s."""
    pkts = []
    base_time = datetime.now(timezone.utc)
    for i in range(55):
        pkts.append({
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "timestamp": base_time + timedelta(seconds=i * 0.1),  # all within 5.5s
        })

    detections = detect_high_connection_rate(pkts)
    assert len(detections) == 1
    assert detections[0]["detection_type"] == "High Connection Rate"


def test_detect_beaconing_regularity():
    """Triggers beaconing rule when connections occur at regular intervals (low variance)."""
    pkts = []
    base_time = datetime.now(timezone.utc)
    # 6 connections spaced exactly 5.0 seconds apart
    for i in range(6):
        pkts.append({
            "src_ip": "192.168.1.20",
            "dst_ip": "203.0.113.10",
            "timestamp": base_time + timedelta(seconds=i * 5.0),
        })

    detections = detect_beaconing(pkts)
    assert len(detections) == 1
    assert detections[0]["detection_type"] == "Possible Beaconing Pattern"


def test_detect_beaconing_irregular_no_trigger():
    """Does NOT trigger beaconing when intervals are completely irregular."""
    pkts = []
    base_time = datetime.now(timezone.utc)
    offsets = [0, 1.0, 21.0, 24.0, 69.0, 71.0]
    for off in offsets:
        pkts.append({
            "src_ip": "192.168.1.20",
            "dst_ip": "203.0.113.10",
            "timestamp": base_time + timedelta(seconds=off),
        })

    detections = detect_beaconing(pkts)
    assert len(detections) == 0


def test_detect_unusual_ports():
    """Detects connections to non-standard ports (e.g. 31337, 4444)."""
    pkts = [
        {"dst_port": 31337, "protocol": "TCP", "dst_ip": "10.0.0.2"},
        {"dst_port": 4444, "protocol": "TCP", "dst_ip": "10.0.0.2"},
    ]
    detections = detect_unusual_ports(pkts)
    assert len(detections) == 1
    assert "31337" in detections[0]["evidence"]


def test_detect_icmp_burst():
    """Triggers ICMP burst rule when >= 20 ICMP packets occur in window."""
    pkts = []
    base_time = datetime.now(timezone.utc)
    for i in range(25):
        pkts.append({
            "protocol": "ICMP",
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.1",
            "timestamp": base_time + timedelta(seconds=i * 0.2),  # within 5s
        })

    detections = detect_icmp_burst(pkts)
    assert len(detections) == 1
    assert detections[0]["detection_type"] == "ICMP Burst / Sweep"


def test_detect_http_cleartext_auth():
    """Detects credentials or tokens exposed in plain HTTP URI."""
    http_events = [{
        "host": "insecure-site.org",
        "uri": "/login?user=admin&password=SuperSecretPassword123",
        "method": "GET",
        "src_ip": "192.168.1.10",
        "dst_ip": "93.184.216.34",
    }]
    detections = detect_http_metadata_anomalies(http_events)
    assert len(detections) == 1
    assert "Cleartext Authentication" in detections[0]["detection_type"]
