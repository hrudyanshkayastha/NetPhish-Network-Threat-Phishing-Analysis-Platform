"""Offline lexical URL parser and domain decomposition.

Strict Security Control:
Never performs DNS resolution, network queries, or HTTP connections.

Author: Hrudyansh Kayastha
"""

from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, Optional

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz",
    "co.jp", "ne.jp", "ac.jp",
    "com.br", "net.br", "org.br",
    "co.in", "net.in", "org.in", "gen.in",
}


def parse_url(raw_url: str) -> Dict[str, Any]:
    """Parses a URL string into standard components completely offline."""
    clean_url = (raw_url or "").strip()
    if not clean_url:
        raise ValueError("URL string cannot be empty.")

    has_scheme = "://" in clean_url
    url_to_parse = clean_url if has_scheme else f"http://{clean_url}"

    parsed = urlparse(url_to_parse)

    scheme = parsed.scheme.lower() if has_scheme else ""
    hostname = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    path = parsed.path or "/"
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    username = parsed.username or ""

    # Canonical normalized URL representation
    netloc = hostname
    if port:
        if not (port == 80 and scheme == "http") and not (port == 443 and scheme == "https"):
            netloc = f"{hostname}:{port}"

    canonical_url = urlunparse((
        scheme or "http",
        netloc,
        path,
        parsed.params,
        query,
        ""  # Exclude fragment for canonical identification
    ))

    # Domain decomposition
    domain_info = decompose_domain(hostname)

    return {
        "raw_url": clean_url,
        "canonical_url": canonical_url,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "username": username,
        **domain_info,
    }


def decompose_domain(hostname: str) -> Dict[str, Any]:
    """Deterministically decomposes a hostname into subdomains, registered domain, and TLD."""
    clean_host = (hostname or "").strip().lower()
    if not clean_host:
        return {
            "full_hostname": "",
            "registered_domain": "",
            "subdomain": "",
            "tld": "",
            "subdomain_count": 0,
            "hostname_depth": 0,
            "is_ipv4": False,
            "is_ip_host": False,
        }

    # Check IPv4
    parts = clean_host.split(".")
    is_ipv4 = len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if is_ipv4:
        return {
            "full_hostname": clean_host,
            "registered_domain": clean_host,
            "subdomain": "",
            "tld": "",
            "subdomain_count": 0,
            "hostname_depth": 1,
            "is_ipv4": True,
            "is_ip_host": True,
        }

    label_count = len(parts)
    if label_count <= 1:
        return {
            "full_hostname": clean_host,
            "registered_domain": clean_host,
            "subdomain": "",
            "tld": "",
            "subdomain_count": 0,
            "hostname_depth": label_count,
            "is_ipv4": False,
            "is_ip_host": False,
        }

    # Multi-part TLD check (e.g., bank.co.uk)
    registered_domain = ""
    subdomain = ""
    tld = ""

    if label_count >= 3:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in MULTI_PART_TLDS:
            tld = two_part
            registered_domain = f"{parts[-3]}.{two_part}"
            subdomain = ".".join(parts[:-3])
        else:
            tld = parts[-1]
            registered_domain = f"{parts[-2]}.{parts[-1]}"
            subdomain = ".".join(parts[:-2])
    else:
        tld = parts[-1]
        registered_domain = clean_host
        subdomain = ""

    subdomain_parts = [p for p in subdomain.split(".") if p]

    return {
        "full_hostname": clean_host,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "tld": tld,
        "subdomain_count": len(subdomain_parts),
        "hostname_depth": label_count,
        "is_ipv4": False,
        "is_ip_host": False,
    }
