"""Deterministic network threat detection heuristics and risk scoring.

Author: Hrudyansh Kayastha
"""

import math
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict, Counter

from app.config import (
    COMMON_PORTS,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SEC,
    HIGH_CONNECTION_RATE_THRESHOLD,
    HIGH_CONNECTION_RATE_WINDOW_SEC,
    BEACONING_MIN_CONNECTIONS,
    BEACONING_MAX_VARIANCE_COEFF,
    ICMP_BURST_THRESHOLD,
    ICMP_BURST_WINDOW_SEC,
    DNS_ANOMALY_DOMAIN_LENGTH,
    DNS_ANOMALY_SUBDOMAIN_DEPTH,
)


def detect_port_scans(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects horizontal or vertical port scanning activity (>= 10 unique ports probed)."""
    scans_map: Dict[tuple, List[int]] = defaultdict(list)
    for pkt in packet_events:
        if pkt.get("protocol") in ("TCP", "UDP"):
            src_ip = pkt.get("src_ip")
            dst_ip = pkt.get("dst_ip")
            dst_port = pkt.get("dst_port")
            if src_ip and dst_ip and dst_port:
                scans_map[(src_ip, dst_ip)].append(dst_port)

    detections = []
    for (src_ip, dst_ip), ports in scans_map.items():
        unique_ports = set(ports)
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            sample_ports = sorted(list(unique_ports))[:6]
            evidence = f"Source host {src_ip} probed {len(unique_ports)} unique destination ports on target {dst_ip} (e.g. ports {sample_ports})"
            detections.append({
                "detection_type": "Possible Port Scan",
                "source": src_ip,
                "destination": dst_ip,
                "evidence": evidence,
                "severity": "HIGH",
                "confidence": "high",
                "points": 20.0,
            })
            break
    return detections


def detect_high_connection_rate(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects connection rate bursts (>= 50 connections/packets within 10s window)."""
    src_times: Dict[str, List[float]] = defaultdict(list)
    for pkt in packet_events:
        src = pkt.get("src_ip")
        ts = pkt.get("timestamp")
        if src and ts:
            epoch = ts.timestamp() if isinstance(ts, datetime) else float(ts)
            src_times[src].append(epoch)

    detections = []
    for src_ip, times in src_times.items():
        if len(times) >= HIGH_CONNECTION_RATE_THRESHOLD:
            times.sort()
            left = 0
            max_in_window = 0
            for right in range(len(times)):
                while times[right] - times[left] > HIGH_CONNECTION_RATE_WINDOW_SEC:
                    left += 1
                curr = right - left + 1
                if curr > max_in_window:
                    max_in_window = curr

            if max_in_window >= HIGH_CONNECTION_RATE_THRESHOLD:
                detections.append({
                    "detection_type": "High Connection Rate",
                    "source": src_ip,
                    "destination": None,
                    "evidence": f"Host {src_ip} initiated {max_in_window} packets within a {HIGH_CONNECTION_RATE_WINDOW_SEC:.0f}s window",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "points": 15.0,
                })
                break
    return detections


def detect_beaconing(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects periodic connection regularity (CV <= 0.35 across >= 4 connections)."""
    pair_times: Dict[tuple, List[float]] = defaultdict(list)
    for pkt in packet_events:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        ts = pkt.get("timestamp")
        if src_ip and dst_ip and ts:
            epoch = ts.timestamp() if isinstance(ts, datetime) else float(ts)
            pair_times[(src_ip, dst_ip)].append(epoch)

    detections = []
    for (src_ip, dst_ip), times in pair_times.items():
        if len(times) >= BEACONING_MIN_CONNECTIONS:
            times.sort()
            intervals = [times[i] - times[i - 1] for i in range(1, len(times)) if times[i] - times[i - 1] > 0.05]
            if len(intervals) >= BEACONING_MIN_CONNECTIONS - 1:
                mean_int = sum(intervals) / len(intervals)
                if mean_int >= 0.5:
                    variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
                    std_dev = math.sqrt(variance)
                    cv = std_dev / mean_int

                    if cv <= BEACONING_MAX_VARIANCE_COEFF:
                        detections.append({
                            "detection_type": "Possible Beaconing Pattern",
                            "source": src_ip,
                            "destination": dst_ip,
                            "evidence": f"Periodic connection regularity: {len(intervals)+1} contacts, avg interval: {mean_int:.2f}s, variance coeff: {cv:.3f}",
                            "severity": "HIGH",
                            "confidence": "high",
                            "points": 20.0,
                        })
                        break
    return detections


def detect_icmp_burst(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects ICMP bursts (>= 20 packets within 10s window)."""
    icmp_times: Dict[tuple, List[float]] = defaultdict(list)
    for pkt in packet_events:
        if pkt.get("protocol") == "ICMP":
            src = pkt.get("src_ip")
            dst = pkt.get("dst_ip")
            ts = pkt.get("timestamp")
            if src and dst and ts:
                epoch = ts.timestamp() if isinstance(ts, datetime) else float(ts)
                icmp_times[(src, dst)].append(epoch)

    detections = []
    for (src_ip, dst_ip), times in icmp_times.items():
        if len(times) >= ICMP_BURST_THRESHOLD:
            times.sort()
            left = 0
            max_burst = 0
            for right in range(len(times)):
                while times[right] - times[left] > ICMP_BURST_WINDOW_SEC:
                    left += 1
                curr = right - left + 1
                if curr > max_burst:
                    max_burst = curr

            if max_burst >= ICMP_BURST_THRESHOLD:
                detections.append({
                    "detection_type": "ICMP Burst / Sweep",
                    "source": src_ip,
                    "destination": dst_ip,
                    "evidence": f"Transmitted {max_burst} ICMP echo packets to {dst_ip} within {ICMP_BURST_WINDOW_SEC:.0f}s",
                    "severity": "MEDIUM",
                    "confidence": "high",
                    "points": 10.0,
                })
                break
    return detections


def detect_unusual_ports(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects destination ports outside the standard common service port list."""
    unusual_ports = set()
    for pkt in packet_events:
        dport = pkt.get("dst_port")
        proto = pkt.get("protocol")
        if dport and proto in ("TCP", "UDP") and dport > 0:
            if dport not in COMMON_PORTS:
                unusual_ports.add(dport)

    detections = []
    if unusual_ports:
        port_list = sorted(list(unusual_ports))[:6]
        detections.append({
            "detection_type": "Unusual Destination Port",
            "source": None,
            "destination": f"Ports {port_list}",
            "evidence": f"Observed traffic destined for non-standard ports: {port_list}",
            "severity": "LOW",
            "confidence": "medium",
            "points": 10.0,
        })
    return detections


def detect_repeated_outbound(packet_events: List[Dict[str, Any]], exclude: bool = False) -> List[Dict[str, Any]]:
    """Detects high-volume repeated communications between a host pair."""
    if exclude:
        return []
    detections = []
    for (src_ip, dst_ip), count in Counter((p.get("src_ip"), p.get("dst_ip")) for p in packet_events).items():
        if count >= 10:
            detections.append({
                "detection_type": "Repeated Outbound Connections",
                "source": src_ip,
                "destination": dst_ip,
                "evidence": f"Persistent communication: {count} packets exchanged between {src_ip} and {dst_ip}",
                "severity": "LOW",
                "confidence": "medium",
                "points": 15.0,
            })
            break
    return detections


def detect_dns_anomalies(dns_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects excessive length or deeply nested subdomain queries."""
    detections = []
    for dns in dns_queries:
        qname = dns.get("qname", "").lower()
        if not qname:
            continue
        labels = qname.split(".")
        if len(qname) > DNS_ANOMALY_DOMAIN_LENGTH or len(labels) >= DNS_ANOMALY_SUBDOMAIN_DEPTH + 1:
            detections.append({
                "detection_type": "DNS Query Anomaly",
                "source": dns.get("src_ip"),
                "destination": dns.get("dst_ip"),
                "evidence": f"Anomalous query string '{qname}' (length: {len(qname)}, labels: {len(labels)})",
                "severity": "MEDIUM",
                "confidence": "high",
                "points": 10.0,
            })
            break
    return detections


def detect_http_metadata_anomalies(http_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detects raw IP Host headers and plaintext credentials in HTTP requests."""
    detections = []
    for http in http_events:
        host = http.get("host", "").lower().split(":")[0]
        uri = http.get("uri", "").lower()
        if all(p.isdigit() for p in host.split(".")) and len(host.split(".")) == 4:
            detections.append({
                "detection_type": "HTTP Direct IP Host Header",
                "source": http.get("src_ip"),
                "destination": f"{host}:{http.get('dst_port')}",
                "evidence": f"HTTP {http.get('method')} request targeting raw IP host header '{host}' (URI: {http.get('uri')[:30]})",
                "severity": "MEDIUM",
                "confidence": "high",
                "points": 10.0,
            })
            break
        elif any(param in uri for param in ["password=", "token=", "auth="]):
            detections.append({
                "detection_type": "Cleartext Authentication in HTTP URI",
                "source": http.get("src_ip"),
                "destination": host,
                "evidence": f"Sensitive credential parameters observed in plaintext HTTP URI: {uri[:40]}",
                "severity": "HIGH",
                "confidence": "high",
                "points": 10.0,
            })
            break
    return detections


def evaluate_network_detections(
    packet_events: List[Dict[str, Any]],
    dns_queries: List[Dict[str, Any]],
    http_events: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], float, str]:
    """Evaluates all deterministic network heuristics and computes unified network risk score."""
    detections: List[Dict[str, Any]] = []
    factors: List[Dict[str, Any]] = []

    # 1. Port scan
    scan_dets = detect_port_scans(packet_events)
    if scan_dets:
        detections.extend(scan_dets)
        factors.append({
            "name": "Port scan",
            "points": 20.0,
            "reason": scan_dets[0]["evidence"],
        })

    # 2. Connection rate
    rate_dets = detect_high_connection_rate(packet_events)
    if rate_dets:
        detections.extend(rate_dets)
        factors.append({
            "name": "High connection rate",
            "points": 15.0,
            "reason": rate_dets[0]["evidence"],
        })

    # 3. Beaconing
    beacon_dets = detect_beaconing(packet_events)
    if beacon_dets:
        detections.extend(beacon_dets)
        factors.append({
            "name": "Beaconing",
            "points": 20.0,
            "reason": beacon_dets[0]["evidence"],
        })

    # 4. ICMP burst
    icmp_dets = detect_icmp_burst(packet_events)
    if icmp_dets:
        detections.extend(icmp_dets)
        factors.append({
            "name": "ICMP burst",
            "points": 10.0,
            "reason": icmp_dets[0]["evidence"],
        })

    # 5. Unusual destination ports
    unusual_dets = detect_unusual_ports(packet_events)
    if unusual_dets:
        detections.extend(unusual_dets)
        factors.append({
            "name": "Unusual port",
            "points": 10.0,
            "reason": unusual_dets[0]["evidence"],
        })

    # 6. Repeated outbound
    repeat_dets = detect_repeated_outbound(packet_events, exclude=bool(scan_dets))
    if repeat_dets:
        detections.extend(repeat_dets)
        factors.append({
            "name": "Repeated outbound",
            "points": 15.0,
            "reason": repeat_dets[0]["evidence"],
        })

    # 7. DNS anomaly
    dns_dets = detect_dns_anomalies(dns_queries)
    if dns_dets:
        detections.extend(dns_dets)
        factors.append({
            "name": "DNS anomaly",
            "points": 10.0,
            "reason": dns_dets[0]["evidence"],
        })

    # 8. Suspicious HTTP metadata
    http_dets = detect_http_metadata_anomalies(http_events)
    if http_dets:
        detections.extend(http_dets)
        factors.append({
            "name": "Suspicious HTTP metadata",
            "points": 10.0,
            "reason": http_dets[0]["evidence"],
        })

    total_score = min(100.0, sum(f["points"] for f in factors))

    if total_score >= 80.0:
        severity = "CRITICAL"
    elif total_score >= 60.0:
        severity = "HIGH"
    elif total_score >= 30.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return detections, factors, total_score, severity
