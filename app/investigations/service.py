"""Investigation lifecycle management service and timeline orchestrator."""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.database.db import (
    Investigation,
    Analysis,
    Detection,
    IOC,
    Correlation,
    TimelineEvent,
    investigation_analyses,
    utc_now,
)
from app.correlation.engine import correlate_evidence
from app.risk.scorer import calculate_unified_risk_score


def generate_investigation_id(db: Session) -> str:
    """Generates next sequential investigation identifier (e.g. INV-0001)."""
    count = db.query(Investigation).count()
    return f"INV-{(count + 1):04d}"


def generate_defensive_recommendations(severity: str, detections: List[Any], correlations: List[Any]) -> List[str]:
    """Generates actionable defensive security recommendations."""
    recs = [
        "Review affected origin host for unauthorized software execution or credential access.",
        "Preserve relevant forensic artifacts (PCAP capture and server authentication logs).",
    ]

    if severity in ("HIGH", "CRITICAL"):
        recs.append("Isolate affected internal host from the local network segment pending triage.")
        recs.append("Block confirmed malicious destination IPs and domains at boundary firewalls and DNS resolvers.")
        recs.append("Force credential rotation for any accounts referenced in target authentication queries.")

    def _get_det_type(d: Any) -> str:
        if isinstance(d, dict):
            return str(d.get("detection_type", ""))
        return str(getattr(d, "detection_type", ""))

    if any("DNS" in _get_det_type(d) for d in detections):
        recs.append("Validate enterprise DNS server logs for anomalous high-frequency queries or tunneling attempts.")

    if correlations:
        recs.append("Inspect perimeter proxy and web gateway logs for secondary requests matching correlated IOCs.")

    return recs


def to_datetime(val: Any) -> datetime:
    """Normalizes timestamps into timezone-aware datetime."""
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    elif isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return utc_now()
    elif isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc)
    return utc_now()


def create_investigation_dossier(
    db: Session,
    title: str,
    analysis_ids: List[int],
    explanation: Optional[str] = None,
) -> Investigation:
    """
    Creates an investigation linking multiple analyses, running cross-source correlation,
    calculating unified threat risk, building a timeline, and generating defensive recommendations.
    """
    inv_id = generate_investigation_id(db)

    # Load analyses
    analyses = db.query(Analysis).filter(Analysis.id.in_(analysis_ids)).all() if analysis_ids else []

    url_analysis = next((a for a in analyses if a.analysis_type == "URL"), None)
    pcap_analysis = next((a for a in analyses if a.analysis_type == "PCAP"), None)

    # Collect IOCs
    url_iocs = []
    pcap_iocs = []

    if url_analysis:
        for i in url_analysis.iocs:
            url_iocs.append({
                "value": i.value,
                "canonical_value": i.canonical_value,
                "type": i.type,
                "source": i.source,
                "confidence": i.confidence,
                "classification": i.classification,
                "first_seen": i.first_seen,
                "last_seen": i.last_seen,
            })

    if pcap_analysis:
        for i in pcap_analysis.iocs:
            pcap_iocs.append({
                "value": i.value,
                "canonical_value": i.canonical_value,
                "type": i.type,
                "source": i.source,
                "confidence": i.confidence,
                "classification": i.classification,
                "first_seen": i.first_seen,
                "last_seen": i.last_seen,
            })

    # Run Correlation Engine
    url_data_dict = {"parsed": url_analysis.details_json.get("parsed", {})} if url_analysis else None
    pcap_data_dict = {
        "dns_queries": pcap_analysis.details_json.get("dns_queries", []),
        "http_events": pcap_analysis.details_json.get("http_events", []),
        "flows": [f for f in pcap_analysis.flows],
        "detections": [d for d in pcap_analysis.detections],
    } if pcap_analysis else None

    corr_res = correlate_evidence(
        url_analysis=url_data_dict,
        pcap_analysis=pcap_data_dict,
        url_iocs=url_iocs,
        pcap_iocs=pcap_iocs,
    )

    # Compute Unified Risk Score (URL: 40, Network: 40, Correlation: 15, Temporal: 15)
    url_score = url_analysis.risk_score if url_analysis else 0.0
    pcap_score = pcap_analysis.risk_score if pcap_analysis else 0.0

    risk_eval = calculate_unified_risk_score(
        url_score_raw=url_score,
        network_score_raw=pcap_score,
        correlation_points=corr_res["correlation_points"],
        temporal_points=corr_res["temporal_points"],
    )

    # Generate Recommendations
    all_detections = []
    for a in analyses:
        all_detections.extend(a.detections)
    recommendations = generate_defensive_recommendations(risk_eval["severity"], all_detections, corr_res["correlations"])

    # Create Investigation entity
    investigation = Investigation(
        id=inv_id,
        title=title,
        status="OPEN",
        risk_score=risk_eval["score"],
        severity=risk_eval["severity"],
        explanation=explanation or risk_eval["explanation"],
        recommendations_json=recommendations,
        created_at=utc_now(),
    )
    db.add(investigation)
    db.flush()

    # Link analyses
    for a in analyses:
        investigation.analyses.append(a)

    # Persist Detections under Investigation
    for a in analyses:
        for d in a.detections:
            inv_det = Detection(
                investigation_id=inv_id,
                detection_type=d.detection_type,
                source=d.source,
                destination=d.destination,
                evidence=d.evidence,
                severity=d.severity,
                confidence=d.confidence,
                points=d.points,
            )
            db.add(inv_det)

    # Persist IOCs under Investigation
    persisted_iocs = set()
    for i in (url_iocs + pcap_iocs):
        key = (i["canonical_value"], i["source"])
        if key not in persisted_iocs:
            persisted_iocs.add(key)
            db_ioc = IOC(
                investigation_id=inv_id,
                value=i["value"],
                canonical_value=i["canonical_value"],
                type=i["type"],
                source=i["source"],
                confidence=i["confidence"],
                classification=i["classification"],
                first_seen=to_datetime(i["first_seen"]),
                last_seen=to_datetime(i["last_seen"]),
            )
            db.add(db_ioc)

    # Persist Correlations
    for c in corr_res["correlations"]:
        db_corr = Correlation(
            investigation_id=inv_id,
            correlation_type=c["correlation_type"],
            ioc_value=c["ioc_value"],
            source_a=c["source_a"],
            source_b=c["source_b"],
            evidence=c["evidence"],
            confidence=c["confidence"],
            points=c["points"],
            time_delta_seconds=c["time_delta_seconds"],
        )
        db.add(db_corr)

    # Build Chronological Timeline Events
    timeline_items: List[Dict[str, Any]] = []

    # 1. URL Analysis Event
    if url_analysis:
        timeline_items.append({
            "timestamp": to_datetime(url_analysis.created_at),
            "event_type": "URL_ANALYZED",
            "source": "DEFENDER_INPUT",
            "destination": url_analysis.target,
            "ioc_value": url_analysis.target,
            "title": f"Static URL Inspection Completed ({url_analysis.severity})",
            "details": f"Target evaluated: {url_analysis.target} (Risk Score: {url_analysis.risk_score:.0f}/100)",
            "points": url_analysis.risk_score,
        })

    # 2. PCAP Traffic Events
    if pcap_analysis:
        # DNS
        for dns in pcap_analysis.details_json.get("dns_queries", []):
            timeline_items.append({
                "timestamp": to_datetime(dns.get("timestamp")),
                "event_type": "DNS_QUERY",
                "source": dns.get("src_ip"),
                "destination": dns.get("dst_ip"),
                "ioc_value": dns.get("qname"),
                "title": f"DNS Query Observed ({dns.get('qtype')})",
                "details": f"Origin host queried name '{dns.get('qname')}' -> answers: {', '.join(dns.get('answers', [])) or 'None'}",
                "points": 0.0,
            })

        # HTTP
        for http in pcap_analysis.details_json.get("http_events", []):
            timeline_items.append({
                "timestamp": to_datetime(http.get("timestamp")),
                "event_type": "HTTP_REQUEST",
                "source": f"{http.get('src_ip')}:{http.get('src_port')}",
                "destination": f"{http.get('dst_ip')}:{http.get('dst_port')}",
                "ioc_value": http.get("host"),
                "title": f"HTTP {http.get('method')} Connection to {http.get('host')}",
                "details": f"URI: {http.get('uri')} (Host: {http.get('host')})",
                "points": 0.0,
            })

        # Top Flows
        for fl in pcap_analysis.flows[:10]:
            timeline_items.append({
                "timestamp": to_datetime(fl.first_seen),
                "event_type": "NETWORK_FLOW",
                "source": f"{fl.src_ip}:{fl.src_port}",
                "destination": f"{fl.dst_ip}:{fl.dst_port}",
                "ioc_value": fl.dst_ip,
                "title": f"Connection Established ({fl.protocol})",
                "details": f"Volume: {fl.packet_count} packets, {fl.byte_count} bytes (duration: {fl.duration}s, flags: {fl.tcp_flags or '-'})",
                "points": 0.0,
            })

    # 3. Detections
    for a in analyses:
        for d in a.detections:
            timeline_items.append({
                "timestamp": to_datetime(d.created_at),
                "event_type": "THREAT_DETECTION",
                "source": d.source,
                "destination": d.destination,
                "ioc_value": d.detection_type,
                "title": f"Heuristic Alert: {d.detection_type}",
                "details": d.evidence,
                "points": d.points,
            })

    # 4. Correlations
    for c in corr_res["correlations"]:
        timeline_items.append({
            "timestamp": utc_now(),
            "event_type": "CORRELATION_CONFIRMED",
            "source": c["source_a"],
            "destination": c["source_b"],
            "ioc_value": c["ioc_value"],
            "title": f"Evidence Correlation: {c['correlation_type']}",
            "details": c["evidence"],
            "points": c["points"],
        })

    # Sort strictly chronologically
    timeline_items.sort(key=lambda x: x["timestamp"])

    for item in timeline_items:
        evt = TimelineEvent(
            investigation_id=inv_id,
            timestamp=item["timestamp"],
            event_type=item["event_type"],
            source=item["source"],
            destination=item["destination"],
            ioc_value=item["ioc_value"],
            title=item["title"],
            details=item["details"],
            points=item["points"],
        )
        db.add(evt)

    db.commit()
    db.refresh(investigation)
    return investigation


def get_investigation_dossier(db: Session, investigation_id: str) -> Optional[Investigation]:
    """Retrieves full investigation record by ID."""
    return db.query(Investigation).filter(Investigation.id == investigation_id).first()
