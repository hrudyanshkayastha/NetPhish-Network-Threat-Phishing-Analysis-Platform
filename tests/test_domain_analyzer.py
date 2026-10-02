"""Unit tests for Domain Decomposition."""

import pytest
from app.url_analysis.parser import decompose_domain


def test_standard_domain_decomposition():
    """Decomposes typical standard hostname."""
    res = decompose_domain("login.accounts.example.com")
    assert res["full_hostname"] == "login.accounts.example.com"
    assert res["registered_domain"] == "example.com"
    assert res["subdomain"] == "login.accounts"
    assert res["tld"] == "com"
    assert res["hostname_depth"] == 4
    assert res["is_ip_host"] is False


def test_multipart_public_suffix():
    """Decomposes multi-part ccTLD (e.g., .co.uk)."""
    res = decompose_domain("portal.secure.bank.co.uk")
    assert res["registered_domain"] == "bank.co.uk"
    assert res["subdomain"] == "portal.secure"
    assert res["tld"] == "co.uk"
    assert res["hostname_depth"] == 5


def test_ip_address_host():
    """Handles raw IP addresses gracefully without false subdomain splitting."""
    res = decompose_domain("192.168.1.10")
    assert res["is_ip_host"] is True
    assert res["registered_domain"] == "192.168.1.10"
    assert res["subdomain"] == ""
    assert res["hostname_depth"] == 1


def test_single_label_host():
    """Handles localhost or internal hostnames."""
    res = decompose_domain("localhost")
    assert res["registered_domain"] == "localhost"
    assert res["subdomain"] == ""
    assert res["hostname_depth"] == 1


def test_empty_or_none_domain():
    """Handles empty or None hostname gracefully."""
    res = decompose_domain("")
    assert res["full_hostname"] == ""
    assert res["hostname_depth"] == 0
