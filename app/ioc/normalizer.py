"""Canonical IOC normalization and IP scope classification.

Author: Hrudyansh Kayastha
"""

import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Optional, Dict, Any

# Documentation & Test Subnets (RFC 5737 / RFC 3849)
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),     # Documentation IPv6
]


class IPScope(dict):
    """Dictionary holding IP scope details with string representation falling back to classification."""
    def __str__(self) -> str:
        return self.get("classification", "Unknown")


def classify_ip_scope(ip_str: str) -> IPScope:
    """Classifies an IP address according to standard IETF RFC scopes.

    Accurately distinguishes RFC 5737 test blocks from RFC 1918 private subnets.
    """
    clean = (ip_str or "").strip().strip("[]")
    if ":" in clean and "%" in clean:
        clean = clean.split("%")[0]

    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return IPScope({
            "ip": clean,
            "classification": "Invalid IP",
            "is_routable": False,
            "is_private": False,
            "is_loopback": False,
        })

    # RFC 5737 Test-Nets checked first
    for doc_net in DOCUMENTATION_NETWORKS:
        if ip_obj in doc_net:
            return IPScope({
                "ip": clean,
                "classification": "Documentation/Test-Net (RFC 5737)",
                "is_routable": False,
                "is_private": False,
                "is_loopback": False,
            })

    if ip_obj.is_loopback:
        return IPScope({
            "ip": clean,
            "classification": "Loopback",
            "is_routable": False,
            "is_private": False,
            "is_loopback": True,
        })
    elif ip_obj.is_link_local:
        return IPScope({
            "ip": clean,
            "classification": "Link-Local",
            "is_routable": False,
            "is_private": False,
            "is_loopback": False,
        })
    elif ip_obj.is_multicast:
        return IPScope({
            "ip": clean,
            "classification": "Multicast",
            "is_routable": False,
            "is_private": False,
            "is_loopback": False,
        })
    elif ip_obj.is_private:
        return IPScope({
            "ip": clean,
            "classification": "Private (RFC 1918 / ULA)",
            "is_routable": False,
            "is_private": True,
            "is_loopback": False,
        })
    elif ip_obj.is_reserved:
        return IPScope({
            "ip": clean,
            "classification": "Reserved / Special",
            "is_routable": False,
            "is_private": False,
            "is_loopback": False,
        })
    elif ip_obj.is_global:
        return IPScope({
            "ip": clean,
            "classification": "Public / Global",
            "is_routable": True,
            "is_private": False,
            "is_loopback": False,
        })

    return IPScope({
        "ip": clean,
        "classification": "Non-Routable",
        "is_routable": False,
        "is_private": False,
        "is_loopback": False,
    })


def normalize_domain(domain: Optional[str]) -> str:
    """Canonicalizes domain or hostname."""
    if not domain:
        return ""
    clean = domain.strip().lower()
    if ":" in clean and not clean.startswith("["):
        clean = clean.split(":")[0]
    return clean.rstrip(".")


def normalize_ip(ip_str: Optional[str]) -> str:
    """Canonicalizes IPv4/IPv6 address.

    Removes zero-padding from decimal octets (e.g. 192.168.001.010 -> 192.168.1.10).
    """
    if not ip_str:
        return ""
    clean = ip_str.strip().strip("[]")
    if ":" in clean and "%" in clean:
        clean = clean.split("%")[0]

    parts = clean.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        clean = ".".join(str(int(p)) for p in parts)

    try:
        return str(ipaddress.ip_address(clean))
    except ValueError:
        return clean.lower()


def normalize_url(url_str: Optional[str]) -> str:
    """Canonicalizes URL string."""
    if not url_str:
        return ""
    clean = url_str.strip()
    if "://" not in clean:
        clean = f"http://{clean}"

    try:
        parsed = urlparse(clean)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port

        netloc = host
        if port:
            if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                netloc = f"{host}:{port}"

        path = parsed.path or "/"

        return urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            parsed.query,
            ""
        ))
    except Exception:
        return clean.lower()


def normalize_url_ioc(url_str: Optional[str]) -> str:
    """Alias for normalize_url."""
    return normalize_url(url_str)


def normalize_ioc(ioc_type: str, value: str) -> str:
    """Normalizes an IOC string value according to its type."""
    t = ioc_type.upper()
    if t in ("IPV4", "IP"):
        return normalize_ip(value)
    elif t in ("DOMAIN", "HOSTNAME"):
        return normalize_domain(value)
    elif t in ("URL",):
        return normalize_url(value)
    elif t in ("HASH", "EMAIL"):
        return value.strip().lower()
    return value.strip()


def canonicalize_ioc(ioc_type: str, value: str) -> str:
    """Alias for normalize_ioc."""
    return normalize_ioc(ioc_type, value)
