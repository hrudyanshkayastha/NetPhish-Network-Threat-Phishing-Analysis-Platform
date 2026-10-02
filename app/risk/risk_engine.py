"""Unified threat scoring engine.

Calculates an explainable composite risk score for consolidated investigations
combining URL indicators, network heuristics, cross-source IOC correlation,
and temporal proximity.
"""

from typing import Dict, Any, List, Optional


def calculate_unified_risk(
    url_score_raw: float,
    network_score_raw: float,
    ioc_correlation_score: float,
    temporal_correlation_score: float,
    all_findings: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Computes a transparent composite risk score out of 100:
      - URL Threat Indicators: up to 40 pts (scaled from URL analysis 0-100)
      - Network Threat Indicators: up to 40 pts (scaled from Network analysis 0-100)
      - Cross-Source IOC Correlation: up to 15 pts
      - Temporal Correlation: up to 15 pts

    Total Cap: 100.
    Risk Levels:
      0–29:   LOW
      30–59:  MEDIUM
      60–79:  HIGH
      80–100: CRITICAL
    """
    # Scale raw URL score (0-100) to max 40 points
    url_component = round(min(40.0, (url_score_raw / 100.0) * 40.0), 1)

    # Scale raw Network score (0-100) to max 40 points
    network_component = round(min(40.0, (network_score_raw / 100.0) * 40.0), 1)

    # IOC Correlation: fixed max 15 points
    corr_component = round(min(15.0, ioc_correlation_score), 1)

    # Temporal Correlation: fixed max 15 points
    temporal_component = round(min(15.0, temporal_correlation_score), 1)

    # Sum and cap
    raw_total = url_component + network_component + corr_component + temporal_component
    total_score = round(min(100.0, raw_total), 1)

    if total_score >= 80.0:
        risk_level = "CRITICAL"
    elif total_score >= 60.0:
        risk_level = "HIGH"
    elif total_score >= 30.0:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Build explainable itemized breakdown
    breakdown: List[Dict[str, Any]] = [
        {
            "name": "Static URL Threat Score",
            "category": "URL_EVIDENCE",
            "score": url_component,
            "details": f"Derived from static phishing indicators (raw score: {url_score_raw:.1f}/100, weighted 40%)",
        },
        {
            "name": "Offline Network Traffic Score",
            "category": "NETWORK_EVIDENCE",
            "score": network_component,
            "details": f"Derived from PCAP flows and behavioral rules (raw score: {network_score_raw:.1f}/100, weighted 40%)",
        },
        {
            "name": "Cross-Source IOC Correlation",
            "category": "CORRELATION",
            "score": corr_component,
            "details": f"Identical entities detected across both URL and Network channels (+{corr_component:.1f}/15 pts)",
        },
        {
            "name": "Temporal Event Proximity",
            "category": "TEMPORAL",
            "score": temporal_component,
            "details": f"Related events occurring within observation window (±5 minutes) (+{temporal_component:.1f}/15 pts)",
        },
    ]

    return {
        "url_score": url_component,
        "network_score": network_component,
        "correlation_score": corr_component,
        "temporal_score": temporal_component,
        "total_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }
