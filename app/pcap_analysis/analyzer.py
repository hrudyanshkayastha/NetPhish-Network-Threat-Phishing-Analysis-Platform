"""Offline PCAP analysis coordinator module."""

from typing import Dict, Any
from app.pcap_analysis.parser import parse_pcap_capture
from app.pcap_analysis.flows import aggregate_network_flows
from app.pcap_analysis.detector import evaluate_network_detections
from app.ioc.extractor import extract_iocs_from_pcap_data


def analyze_pcap_file(file_path: str) -> Dict[str, Any]:
    """
    Coordinates offline parsing, flow aggregation, network detection heuristics,
    and IOC extraction for a PCAP/PCAPNG capture file.
    """
    # 1. Parse packet records offline
    capture_data = parse_pcap_capture(file_path)

    # 2. Aggregate 5-tuple logical connection flows
    flows = aggregate_network_flows(capture_data["packets"])

    # 3. Evaluate deterministic network detections and risk score
    detections, factors, risk_score, severity = evaluate_network_detections(
        capture_data["packets"],
        capture_data["dns_queries"],
        capture_data["http_events"],
    )

    # 4. Generate summary
    if risk_score >= 60.0:
        summary = f"High-risk network anomaly profile identified ({len(detections)} detection rules triggered across {len(flows)} flows)."
    elif risk_score >= 30.0:
        summary = f"Suspicious network activity detected ({len(detections)} detection rules triggered). Requires further triage."
    else:
        summary = f"Normal traffic baseline ({len(flows)} flows aggregated across {capture_data['packet_count']} packets)."

    # 5. Extract IOCs
    iocs = extract_iocs_from_pcap_data({
        "file_hash": capture_data["file_hash"],
        "flows": flows,
        "dns_queries": capture_data["dns_queries"],
        "http_events": capture_data["http_events"],
    })

    return {
        "filename": capture_data["filename"],
        "file_hash": capture_data["file_hash"],
        "packet_count": capture_data["packet_count"],
        "flow_count": len(flows),
        "duration_seconds": capture_data["duration_seconds"],
        "risk_score": risk_score,
        "severity": severity,
        "summary": summary,
        "protocols": capture_data["protocols"],
        "flows": flows,
        "detections": detections,
        "factors": factors,
        "iocs": iocs,
        "dns_queries": capture_data["dns_queries"],
        "http_events": capture_data["http_events"],
    }
