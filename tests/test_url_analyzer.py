"""Unit tests for Static URL Analyzer and Phishing Detection Rules."""

import pytest
from unittest.mock import patch

from app.url_analysis.parser import parse_url
from app.url_analysis.analyzer import analyze_url_target


def test_url_normalization_basic():
    """Verifies basic URL parsing, lowercasing, and default port handling."""
    res = parse_url("HTTPS://EXAMPLE.COM:443/Login/Path/")
    assert res["scheme"] == "https"
    assert res["hostname"] == "example.com"
    assert res["port"] == 443
    assert res["canonical_url"] == "https://example.com/Login/Path/"


def test_url_normalization_missing_scheme():
    """Verifies that URLs without a scheme are safely handled."""
    res = parse_url("attacker.xyz/verify")
    assert res["hostname"] == "attacker.xyz"
    assert res["path"] == "/verify"


def test_url_normalization_custom_port():
    """Verifies custom port preservation in normalized representation."""
    res = parse_url("http://192.168.1.50:8080/admin")
    assert res["port"] == 8080
    assert ":8080" in res["canonical_url"]


def test_ip_hostname_detection():
    """Detects raw IP addresses used directly as hostnames."""
    analysis = analyze_url_target("http://192.168.1.10/login")
    assert analysis["features"]["is_ip_host"] is True
    assert any("Raw IP" in d["detection_type"] for d in analysis["detections"])
    assert analysis["risk_score"] >= 35.0  # IP host (+20) + HTTP (+15)


def test_unencrypted_http_detection():
    """Flags unencrypted HTTP transport."""
    analysis = analyze_url_target("http://example.com/test")
    assert any("Unencrypted" in d["detection_type"] for d in analysis["detections"])


def test_clean_https_url():
    """Clean HTTPS URL produces LOW risk posture with zero suspicious flags."""
    analysis = analyze_url_target("https://www.google.com")
    assert analysis["severity"] == "LOW"
    assert analysis["risk_score"] < 30.0


def test_suspicious_keyword_detection():
    """Identifies authentication and financial keywords in path/subdomain."""
    analysis = analyze_url_target("https://example.com/banking/account/verify/password")
    assert any("Suspicious Keyword" in d["detection_type"] for d in analysis["detections"])


def test_url_shortener_detection():
    """Detects redirection shorteners like tinyurl or bit.ly."""
    analysis = analyze_url_target("http://tinyurl.com/account-update")
    assert any("Shortener" in d["detection_type"] for d in analysis["detections"])


def test_punycode_detection():
    """Detects Punycode (IDN homograph) hostnames."""
    analysis = analyze_url_target("http://xn--microsft-e1a.xyz/login")
    assert any("Punycode" in d["detection_type"] for d in analysis["detections"])


def test_suspicious_tld_detection():
    """Flags high-risk disposable TLDs (.xyz, .top, etc.)."""
    analysis = analyze_url_target("https://login-support.xyz/update")
    assert any("High-Risk TLD" in d["detection_type"] for d in analysis["detections"])


def test_at_symbol_obfuscation():
    """Detects user credential authority delimiters hiding true destination."""
    analysis = analyze_url_target("http://paypal.com@attacker-portal.net/login")
    assert any("@ Symbol" in d["detection_type"] for d in analysis["detections"])


def test_excessive_subdomains():
    """Flags deep subdomain chains designed to push true host offscreen."""
    analysis = analyze_url_target("http://login.verify.account.security.target.com.attacker.org/auth")
    assert any("Subdomain" in d["detection_type"] for d in analysis["detections"])


def test_character_density_and_length():
    """Detects high density of punctuation characters and long query strings."""
    long_url = "https://example.com/test?token=abc-123_xyz%20&auth=yes--sec==foo@@bar__12345678901234567890"
    analysis = analyze_url_target(long_url)
    assert any("Character Density" in d["detection_type"] for d in analysis["detections"])


def test_percent_encoding_detection():
    """Detects excessive percent encoding in path or query."""
    analysis = analyze_url_target("http://example.com/%2e%2e/%2fadmin%20test")
    assert any("Percent-Encoding" in d["detection_type"] for d in analysis["detections"])


def test_repeated_separators():
    """Detects repeated hyphens or multiple slashes."""
    analysis = analyze_url_target("http://example--bank.com//path//to//login")
    assert any("Separator" in d["detection_type"] for d in analysis["detections"])


def test_brand_hostname_mismatch():
    """Flags well-known brand keywords residing strictly in path while domain is unrelated."""
    analysis = analyze_url_target("http://unrelated-domain.xyz/login/paypal/verify")
    assert any("Brand Name Mismatch" in d["detection_type"] for d in analysis["detections"])


def test_zero_network_calls_assertion():
    """
    CRITICAL SECURITY TEST:
    Verifies that static URL analysis NEVER initiates network sockets or connections.
    """
    with patch("socket.socket") as mock_socket, \
         patch("urllib.request.urlopen") as mock_urlopen:
        analysis = analyze_url_target("http://malicious-phishing-test-domain.xyz/exploit")
        assert analysis is not None
        mock_socket.assert_not_called()
        mock_urlopen.assert_not_called()


def test_score_capping_and_deduplication():
    """Verifies that combined indicators are properly capped at 100."""
    extreme_url = "http://192.168.1.10:8080/paypal/login/verify/bank/update/password?token=%20%20%20&at=@&dash=----"
    analysis = analyze_url_target(extreme_url)
    assert analysis["risk_score"] <= 100.0
    assert analysis["severity"] in ("HIGH", "CRITICAL")


def test_empty_url_handling():
    """Verifies that empty string or whitespace raises ValueError cleanly."""
    with pytest.raises(ValueError):
        analyze_url_target("   ")
