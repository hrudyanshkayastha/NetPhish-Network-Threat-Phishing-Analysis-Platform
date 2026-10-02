"""Multi-source IOC extractor with provenance tracking."""

from typing import List, Dict, Any
from datetime import datetime, timezone
import re

from app.ioc.normalizer import normalize_ioc, classify_ip_scope


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def extract_iocs_from_url_data(parsed_url: Dict[str, Any], risk_score: float = 0.0, severity: str = "LOW") -> List[Dict[str, Any]]:
    """
    Extracts normalized IOCs (URL, Hostname, Domain, IPv4) from static URL analysis.
    """
    iocs: List[Dict[str, Any]] = []
    now = utc_now()

    raw_url = parsed_url.get("raw_url", "")
    hostname = parsed_url.get("hostname", "")
    reg_domain = parsed_url.get("registered_domain", "")
    is_ipv4 = parsed_url.get("is_ipv4", False)

    # 1. URL IOC
    if raw_url:
        canon_url = normalize_ioc("URL", raw_url)
        confidence = "high" if risk_score >= 60.0 else ("medium" if risk_score >= 30.0 else "low")
        iocs.append({
            "type": "URL",
            "value": raw_url,
            "canonical_value": canon_url,
            "source": "URL_ANALYSIS",
            "confidence": confidence,
            "classification": f"Risk Rating: {severity} ({risk_score:.0f}/100)",
            "first_seen": now,
            "last_seen": now,
        })

    # 2. Host IOC (IPv4 or Domain)
    if hostname:
        if is_ipv4:
            canon_ip = normalize_ioc("IPv4", hostname)
            scope = classify_ip_scope(hostname)
            iocs.append({
                "type": "IPv4",
                "value": hostname,
                "canonical_value": canon_ip,
                "source": "URL_ANALYSIS",
                "confidence": "high",
                "classification": str(scope),
                "first_seen": now,
                "last_seen": now,
            })
        else:
            canon_host = normalize_ioc("DOMAIN", hostname)
            iocs.append({
                "type": "DOMAIN",
                "value": hostname,
                "canonical_value": canon_host,
                "source": "URL_ANALYSIS",
                "confidence": "medium",
                "classification": f"FQDN (Depth: {parsed_url.get('hostname_depth', 1)})",
                "first_seen": now,
                "last_seen": now,
            })

    # 3. Registered Domain IOC
    if reg_domain and not is_ipv4 and reg_domain != hostname:
        canon_dom = normalize_ioc("DOMAIN", reg_domain)
        iocs.append({
            "type": "DOMAIN",
            "value": reg_domain,
            "canonical_value": canon_dom,
            "source": "URL_ANALYSIS",
            "confidence": "medium",
            "classification": f"Registered Domain (TLD: .{parsed_url.get('tld', '')})",
            "first_seen": now,
            "last_seen": now,
        })

    # 4. Check for emails in URI parameters (credential harvesting patterns)
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", raw_url)
    for em in set(emails):
        iocs.append({
            "type": "EMAIL",
            "value": em,
            "canonical_value": em.lower(),
            "source": "URL_ANALYSIS",
            "confidence": "medium",
            "classification": "Target Email in Query Parameter",
            "first_seen": now,
            "last_seen": now,
        })

    return iocs


def extract_iocs_from_pcap_data(pcap_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts normalized IOCs (IPv4, DOMAIN, HASH) from PCAP flow and protocol analysis.
    """
    iocs_map: Dict[tuple, Dict[str, Any]] = {}
    now = utc_now()

    # File SHA-256 Hash
    file_hash = pcap_data.get("file_hash")
    if file_hash:
        key = ("HASH", file_hash.lower())
        iocs_map[key] = {
            "type": "HASH",
            "value": file_hash,
            "canonical_value": file_hash.lower(),
            "source": "PCAP_METADATA",
            "confidence": "high",
            "classification": "SHA-256 Capture Hash",
            "first_seen": now,
            "last_seen": now,
        }

    # Extract from Flows
    for flow in pcap_data.get("flows", []):
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        first_seen = flow.get("first_seen") or now
        last_seen = flow.get("last_seen") or now

        for ip_val, role in [(src_ip, "Source Host"), (dst_ip, "Destination Host")]:
            if ip_val and ":" not in ip_val:  # IPv4
                canon_ip = normalize_ioc("IPv4", ip_val)
                scope = classify_ip_scope(ip_val)
                key = ("IPv4", canon_ip)
                if key not in iocs_map:
                    iocs_map[key] = {
                        "type": "IPv4",
                        "value": ip_val,
                        "canonical_value": canon_ip,
                        "source": "PCAP_FLOW",
                        "confidence": "high",
                        "classification": f"{scope} ({role})",
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    }

    # Extract from DNS Queries & Answers
    for dns in pcap_data.get("dns_queries", []):
        qname = dns.get("qname")
        ts = dns.get("timestamp") or now
        if qname:
            canon_dom = normalize_ioc("DOMAIN", qname)
            key = ("DOMAIN", canon_dom)
            if key not in iocs_map:
                iocs_map[key] = {
                    "type": "DOMAIN",
                    "value": qname,
                    "canonical_value": canon_dom,
                    "source": "DNS_QUERY",
                    "confidence": "high",
                    "classification": f"DNS {dns.get('qtype', 'A')} Record Query",
                    "first_seen": ts,
                    "last_seen": ts,
                }

        # Extracted IP Answers
        for ans in dns.get("answers", []):
            if ans and ":" not in ans and "." in ans:
                canon_ip = normalize_ioc("IPv4", ans)
                scope = classify_ip_scope(ans)
                key = ("IPv4", canon_ip)
                if key not in iocs_map:
                    iocs_map[key] = {
                        "type": "IPv4",
                        "value": ans,
                        "canonical_value": canon_ip,
                        "source": "DNS_QUERY",
                        "confidence": "high",
                        "classification": f"{scope} (DNS Resolution Answer)",
                        "first_seen": ts,
                        "last_seen": ts,
                    }

    # Extract from HTTP Metadata
    for http in pcap_data.get("http_events", []):
        host = http.get("host")
        ts = http.get("timestamp") or now
        if host:
            # Check if host is IPv4 or Domain
            parts = host.split(":")
            host_no_port = parts[0]
            if all(p.isdigit() for p in host_no_port.split(".")) and len(host_no_port.split(".")) == 4:
                canon_ip = normalize_ioc("IPv4", host_no_port)
                key = ("IPv4", canon_ip)
                if key not in iocs_map:
                    iocs_map[key] = {
                        "type": "IPv4",
                        "value": host_no_port,
                        "canonical_value": canon_ip,
                        "source": "HTTP_METADATA",
                        "confidence": "high",
                        "classification": "HTTP Host Header (Direct IP)",
                        "first_seen": ts,
                        "last_seen": ts,
                    }
            else:
                canon_dom = normalize_ioc("DOMAIN", host_no_port)
                key = ("DOMAIN", canon_dom)
                if key not in iocs_map:
                    iocs_map[key] = {
                        "type": "DOMAIN",
                        "value": host_no_port,
                        "canonical_value": canon_dom,
                        "source": "HTTP_METADATA",
                        "confidence": "high",
                        "classification": "HTTP Host Header",
                        "first_seen": ts,
                        "last_seen": ts,
                    }

    return list(iocs_map.values())
