"""Unit tests for IOC Intelligence, Normalization, and IP Classification."""

import pytest
from app.ioc.normalizer import (
    classify_ip_scope,
    normalize_domain,
    normalize_ip,
    normalize_url_ioc,
    canonicalize_ioc,
)
from app.ioc.extractor import (
    extract_iocs_from_url_data,
    extract_iocs_from_pcap_data,
)


def test_ip_classification_private():
    """Identifies RFC1918 private subnets."""
    assert classify_ip_scope("192.168.1.1")["classification"] == "Private (RFC 1918 / ULA)"
    assert classify_ip_scope("10.0.0.1")["classification"] == "Private (RFC 1918 / ULA)"
    assert classify_ip_scope("172.16.5.10")["classification"] == "Private (RFC 1918 / ULA)"


def test_ip_classification_documentation():
    """
    CRITICAL REQUIREMENT:
    Documentation/Test-Net IPs (RFC 5737) must NOT be labeled as RFC1918 private addresses!
    """
    res1 = classify_ip_scope("203.0.113.50")  # TEST-NET-3
    assert res1["classification"] == "Documentation/Test-Net (RFC 5737)"
    assert res1["is_routable"] is False

    res2 = classify_ip_scope("198.51.100.25")  # TEST-NET-2
    assert res2["classification"] == "Documentation/Test-Net (RFC 5737)"

    res3 = classify_ip_scope("192.0.2.1")  # TEST-NET-1
    assert res3["classification"] == "Documentation/Test-Net (RFC 5737)"


def test_ip_classification_loopback():
    """Identifies loopback addresses."""
    assert classify_ip_scope("127.0.0.1")["classification"] == "Loopback"


def test_ip_classification_public():
    """Identifies public global routable IP addresses."""
    res = classify_ip_scope("8.8.8.8")
    assert res["classification"] == "Public / Global"
    assert res["is_routable"] is True


def test_ioc_normalization_domain():
    """Normalizes domains to lowercase, stripped dots, and port stripped."""
    assert normalize_domain("  EXAMPLE.COM. ") == "example.com"
    assert normalize_domain("sub.Target.ORG:8080") == "sub.target.org"


def test_ioc_normalization_ip():
    """Normalizes zero-padded and canonical IP representations."""
    assert normalize_ip("192.168.001.010") == "192.168.1.10"
    assert normalize_ip("[2001:db8::1]") == "2001:db8::1"


def test_ioc_normalization_url():
    """Canonicalizes URL representation."""
    norm = normalize_url_ioc("HTTPS://Example.COM:443/Login/Verify#section")
    assert norm == "https://example.com/Login/Verify"


def test_extract_iocs_from_url():
    """Extracts URL, Hostname, and Domain IOCs from static URL analysis."""
    parsed_info = {
        "raw_url": "http://login.bank.xyz/verify",
        "canonical_url": "http://login.bank.xyz/verify",
        "hostname": "login.bank.xyz",
        "registered_domain": "bank.xyz",
        "is_ip_host": False,
        "scheme": "http",
        "tld": "xyz",
    }
    iocs = extract_iocs_from_url_data(parsed_info, risk_score=45.0, severity="MEDIUM")
    types = [i["type"] for i in iocs]
    assert "URL" in types
    assert "DOMAIN" in types


def test_extract_iocs_from_network():
    """Extracts IP, Port, and DNS IOCs from network capture analysis."""
    net_data = {
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "flows": [{
            "src_ip": "192.168.1.50",
            "dst_ip": "203.0.113.10",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_count": 10,
        }],
        "dns_queries": [{
            "qname": "example.com",
            "qtype": "A",
            "src_ip": "192.168.1.50",
            "dst_ip": "1.1.1.1",
            "answers": ["93.184.216.34"],
        }],
        "http_events": [],
    }
    iocs = extract_iocs_from_pcap_data(net_data)
    canon_vals = [i["canonical_value"] for i in iocs]
    assert "192.168.1.50" in canon_vals
    assert "203.0.113.10" in canon_vals
    assert "example.com" in canon_vals
    assert "93.184.216.34" in canon_vals
