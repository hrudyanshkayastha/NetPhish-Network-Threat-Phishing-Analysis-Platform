"""Cross-source and temporal correlation engine."""

from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from app.config import TEMPORAL_WINDOW_SECONDS


def correlate_evidence(
    url_analysis: Optional[Dict[str, Any]],
    pcap_analysis: Optional[Dict[str, Any]],
    url_iocs: List[Dict[str, Any]],
    pcap_iocs: List[Dict[str, Any]],
    temporal_window_sec: float = TEMPORAL_WINDOW_SECONDS,
) -> Dict[str, Any]:
    """
    Correlates security telemetry between static URL analysis and PCAP network capture.
    Maps cross-source relationships (URL -> DOMAIN -> DNS -> IP -> FLOW -> DETECTION).
    """
    correlations: List[Dict[str, Any]] = []
    correlation_points = 0.0

    if not url_analysis or not pcap_analysis:
        return {
            "correlations": [],
            "correlation_points": 0.0,
            "temporal_points": 0.0,
            "total_points": 0.0,
            "relationships": [],
        }

    # Index IOCs by canonical value
    url_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    pcap_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for ioc in url_iocs:
        canon = ioc.get("canonical_value")
        if canon:
            url_map[canon].append(ioc)

    for ioc in pcap_iocs:
        canon = ioc.get("canonical_value")
        if canon:
            pcap_map[canon].append(ioc)

    matched_canons = set(url_map.keys()) & set(pcap_map.keys())

    # 1. Exact Cross-Source Matching
    for canon in matched_canons:
        u_list = url_map[canon]
        p_list = pcap_map[canon]

        for u in u_list:
            for p in p_list:
                corr_type = f"CROSS_SOURCE_{u['type']}_MATCH"
                evidence = (
                    f"Identical indicator '{canon}' ({u['type']}) detected in both "
                    f"URL analysis [{u['source']}] and Network Traffic [{p['source']}]."
                )

                time_delta = None
                u_ts = u.get("first_seen")
                p_ts = p.get("first_seen")
                if isinstance(u_ts, datetime) and isinstance(p_ts, datetime):
                    time_delta = abs((u_ts - p_ts).total_seconds())

                correlations.append({
                    "correlation_type": corr_type,
                    "ioc_value": canon,
                    "source_a": u["source"],
                    "source_b": p["source"],
                    "evidence": evidence,
                    "confidence": "high",
                    "points": 15.0,
                    "time_delta_seconds": time_delta,
                })

                # Temporal Proximity Evaluation
                if time_delta is not None and time_delta <= temporal_window_sec:
                    correlations.append({
                        "correlation_type": "TEMPORAL_COINCIDENCE",
                        "ioc_value": canon,
                        "source_a": u["source"],
                        "source_b": p["source"],
                        "evidence": f"Temporal proximity: Indicator '{canon}' observed across channels within {time_delta:.1f}s (window: {temporal_window_sec:.0f}s).",
                        "confidence": "high",
                        "points": 15.0,
                        "time_delta_seconds": time_delta,
                    })

    # 2. Domain to DNS Substring Matching
    parsed_url = url_analysis.get("parsed", {})
    url_domain = parsed_url.get("registered_domain", "").lower()
    url_host = parsed_url.get("hostname", "").lower()

    for dns in pcap_analysis.get("dns_queries", []):
        qname = dns.get("qname", "").lower()
        if qname and ((url_domain and url_domain in qname) or (url_host and url_host == qname)):
            if not any(c["ioc_value"] == qname for c in correlations):
                correlations.append({
                    "correlation_type": "URL_DOMAIN_TO_DNS_QUERY",
                    "ioc_value": qname,
                    "source_a": "URL_ANALYSIS",
                    "source_b": "DNS_QUERY",
                    "evidence": f"URL hostname/domain '{url_host}' corresponds to network DNS query for '{qname}'.",
                    "confidence": "high",
                    "points": 15.0,
                    "time_delta_seconds": None,
                })

    # Build Attack Chain Relationships
    relationships = []
    if url_analysis:
        relationships.append({"from": "URL", "to": "DOMAIN", "label": "lexical decomposition"})
    if pcap_analysis.get("dns_queries"):
        relationships.append({"from": "DOMAIN", "to": "DNS", "label": "query resolution"})
    if pcap_analysis.get("flows"):
        relationships.append({"from": "DNS", "to": "IP", "label": "resolved destination"})
        relationships.append({"from": "IP", "to": "NETWORK FLOW", "label": "5-tuple connection"})
    if pcap_analysis.get("detections"):
        relationships.append({"from": "NETWORK FLOW", "to": "DETECTION", "label": "heuristic trigger"})

    # Calculate points
    has_ioc_match = any(c["correlation_type"].startswith("CROSS_SOURCE") for c in correlations)
    has_temporal = any(c["correlation_type"] == "TEMPORAL_COINCIDENCE" for c in correlations)

    ioc_pts = 15.0 if has_ioc_match else 0.0
    temp_pts = 15.0 if has_temporal else 0.0
    total_pts = min(30.0, ioc_pts + temp_pts)

    return {
        "correlations": correlations,
        "correlation_points": ioc_pts,
        "temporal_points": temp_pts,
        "total_points": total_pts,
        "relationships": relationships,
    }
