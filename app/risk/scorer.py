"""Unified deterministic risk scoring engine.

Author: Hrudyansh Kayastha
"""

from typing import Dict, Any, List


def calculate_unified_risk_score(
    url_score_raw: float,
    network_score_raw: float,
    correlation_points: float,
    temporal_points: float,
    ioc_confidence_points: float = 0.0,
) -> Dict[str, Any]:
    """Computes an explainable composite threat risk score capped at 100:

      - Static URL Threat Component: up to 40.0 pts (40% weight)
      - Offline Network Threat Component: up to 40.0 pts (40% weight)
      - Cross-Source Evidence Correlation: up to 15.0 pts
      - Temporal Proximity Alignment: up to 15.0 pts
      - Optional High-Confidence Indicator Multiplier: up to 10.0 pts (default: 0.0)
    """
    url_comp = round(min(40.0, (url_score_raw / 100.0) * 40.0), 1)
    net_comp = round(min(40.0, (network_score_raw / 100.0) * 40.0), 1)
    corr_comp = round(min(15.0, correlation_points), 1)
    temp_comp = round(min(15.0, temporal_points), 1)
    ioc_comp = round(min(10.0, ioc_confidence_points), 1)

    raw_sum = url_comp + net_comp + corr_comp + temp_comp + ioc_comp
    final_score = round(min(100.0, raw_sum), 1)

    if final_score >= 80.0:
        severity = "CRITICAL"
        explanation = "Multiple high-severity indicators and correlated network activity demonstrate severe threat characteristics requiring immediate containment."
    elif final_score >= 60.0:
        severity = "HIGH"
        explanation = "Suspicious phishing signals and correlated network indicators present high probability of malicious compromise."
    elif final_score >= 30.0:
        severity = "MEDIUM"
        explanation = "Anomalous patterns observed across telemetry. Requires security analyst triage and validation."
    else:
        severity = "LOW"
        explanation = "Baseline activity. No significant deceptive phishing patterns or anomalous network activity detected."

    contributing_factors = [
        {
            "name": "Static URL Threat Signals",
            "points": url_comp,
            "reason": f"Derived from lexical and structural phishing heuristics ({url_score_raw:.0f}/100 raw, weighted 40%)",
        },
        {
            "name": "Offline Network Anomaly Signals",
            "points": net_comp,
            "reason": f"Derived from PCAP flows, port scans, and beaconing rules ({network_score_raw:.0f}/100 raw, weighted 40%)",
        },
        {
            "name": "Cross-Source Evidence Correlation",
            "points": corr_comp,
            "reason": f"Identical entities confirmed across both URL and Network channels (+{corr_comp:.1f} pts)",
        },
        {
            "name": "Temporal Event Alignment",
            "points": temp_comp,
            "reason": f"Related indicators observed within synchronized observation window (+{temp_comp:.1f} pts)",
        },
    ]

    if ioc_comp > 0:
        contributing_factors.append({
            "name": "High-Confidence IOC Provenance",
            "points": ioc_comp,
            "reason": f"High-confidence IOCs detected across active communication sessions (+{ioc_comp:.1f} pts)",
        })

    return {
        "score": final_score,
        "final_risk_score": final_score,
        "severity": severity,
        "explanation": explanation,
        "url_component": url_comp,
        "network_component": net_comp,
        "correlation_component": corr_comp,
        "temporal_component": temp_comp,
        "ioc_component": ioc_comp,
        "contributing_factors": contributing_factors,
        "components": {
            "url_component": url_comp,
            "network_component": net_comp,
            "correlation_component": corr_comp,
            "temporal_component": temp_comp,
            "ioc_component": ioc_comp,
        },
    }
