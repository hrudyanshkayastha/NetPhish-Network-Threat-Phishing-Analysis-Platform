"""Unit tests for Cross-Source and Temporal Correlation Engine."""

import pytest
from datetime import datetime, timezone, timedelta
from app.correlation.engine import correlate_evidence


def test_cross_source_ip_correlation():
    """Identifies exact match when URL host IP matches PCAP destination IP."""
    base_time = datetime.now(timezone.utc)
    url_data = {
        "raw_url": "http://203.0.113.50/login/verify",
        "parsed": {"hostname": "203.0.113.50", "registered_domain": ""},
    }
    pcap_data = {
        "dns_queries": [],
        "http_events": [],
    }

    url_iocs = [{
        "type": "IPv4",
        "canonical_value": "203.0.113.50",
        "source": "URL_ANALYSIS",
        "first_seen": base_time,
    }]

    pcap_iocs = [{
        "type": "IPv4",
        "canonical_value": "203.0.113.50",
        "source": "PCAP_FLOW",
        "first_seen": base_time + timedelta(seconds=60),  # 1 min later
    }]

    res = correlate_evidence(
        url_analysis=url_data,
        pcap_analysis=pcap_data,
        url_iocs=url_iocs,
        pcap_iocs=pcap_iocs,
        temporal_window_sec=300.0,
    )

    assert len(res["correlations"]) >= 1
    assert any(c["ioc_value"] == "203.0.113.50" for c in res["correlations"])
    assert res["correlation_points"] == 15.0

    # Within 60 seconds -> also triggers temporal correlation!
    assert res["temporal_points"] == 15.0
    assert res["total_points"] == 30.0


def test_temporal_correlation_outside_window():
    """Does NOT trigger temporal correlation if events occurred 10 minutes apart."""
    base_time = datetime.now(timezone.utc)
    url_data = {"parsed": {"hostname": "203.0.113.50"}}
    pcap_data = {"dns_queries": [], "http_events": []}

    url_iocs = [{
        "type": "IPv4",
        "canonical_value": "203.0.113.50",
        "source": "URL_ANALYSIS",
        "first_seen": base_time,
    }]

    pcap_iocs = [{
        "type": "IPv4",
        "canonical_value": "203.0.113.50",
        "source": "PCAP_FLOW",
        "first_seen": base_time + timedelta(seconds=600),  # 10 min later (> 300s window)
    }]

    res = correlate_evidence(
        url_analysis=url_data,
        pcap_analysis=pcap_data,
        url_iocs=url_iocs,
        pcap_iocs=pcap_iocs,
        temporal_window_sec=300.0,
    )

    assert len(res["correlations"]) >= 1
    assert res["temporal_points"] == 0.0
    assert res["total_points"] == 15.0


def test_missing_data_correlation_safe():
    """Handles cases where URL or PCAP data is missing without errors."""
    res = correlate_evidence(
        url_analysis=None,
        pcap_analysis={},
        url_iocs=[],
        pcap_iocs=[],
    )
    assert res["total_points"] == 0.0
    assert len(res["correlations"]) == 0
