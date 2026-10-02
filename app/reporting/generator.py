"""Forensic reporting module for NetPhish.

Generates standardized JSON and self-contained HTML forensic dossiers
documenting correlated URL and PCAP threat analyses.

Author: Hrudyansh Kayastha
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import REPORTS_DIR, APP_NAME, APP_VERSION, AUTHOR
from app.database.db import Investigation, Report, utc_now


def _json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def generate_json_report(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Generates and persists a structured JSON forensic dossier for an investigation.

    Args:
        db: SQLAlchemy database session.
        investigation_id: Unique investigation identifier (e.g., INV-0001).

    Returns:
        Dictionary representation of the complete forensic report.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation '{investigation_id}' not found.")

    analyses_payload = []
    flows_payload = []

    for a in inv.analyses:
        analyses_payload.append({
            "id": a.id,
            "analysis_type": a.analysis_type,
            "target": a.target,
            "status": a.status,
            "risk_score": a.risk_score,
            "severity": a.severity,
            "summary": a.summary,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
            "details": a.details_json or {},
        })
        if a.flows:
            for f in a.flows[:100]:  # Cap flows at 100 in summary report
                flows_payload.append({
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "packet_count": f.packet_count,
                    "byte_count": f.byte_count,
                    "duration": f.duration,
                    "tcp_flags": f.tcp_flags,
                })

    detections_payload = [
        {
            "id": d.id,
            "detection_type": d.detection_type,
            "severity": d.severity,
            "confidence": d.confidence,
            "points": d.points,
            "source": d.source,
            "destination": d.destination,
            "evidence": d.evidence,
        }
        for d in inv.detections
    ]

    iocs_payload = [
        {
            "id": i.id,
            "type": i.type,
            "value": i.value,
            "canonical_value": i.canonical_value,
            "source": i.source,
            "confidence": i.confidence,
            "classification": i.classification,
        }
        for i in inv.iocs
    ]

    correlations_payload = [
        {
            "id": c.id,
            "correlation_type": c.correlation_type,
            "ioc_value": c.ioc_value,
            "source_a": c.source_a,
            "source_b": c.source_b,
            "evidence": c.evidence,
            "points": c.points,
            "confidence": c.confidence,
            "time_delta_seconds": c.time_delta_seconds,
        }
        for c in inv.correlations
    ]

    timeline_payload = [
        {
            "id": t.id,
            "timestamp": t.timestamp.isoformat() if t.timestamp else None,
            "event_type": t.event_type,
            "title": t.title,
            "source": t.source,
            "destination": t.destination,
            "ioc_value": t.ioc_value,
            "points": t.points,
            "details": t.details,
        }
        for t in sorted(inv.timeline_events, key=lambda x: x.timestamp or utc_now())
    ]

    report_data = {
        "report_metadata": {
            "platform": APP_NAME,
            "version": APP_VERSION,
            "author": AUTHOR,
            "generated_at": utc_now().isoformat(),
            "report_type": "JSON_FORENSIC_DOSSIER",
        },
        "investigation": {
            "id": inv.id,
            "title": inv.title,
            "status": inv.status,
            "risk_score": inv.risk_score,
            "severity": inv.severity,
            "explanation": inv.explanation,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "recommendations": inv.recommendations_json or [],
        },
        "analyses": analyses_payload,
        "threat_detections": detections_payload,
        "indicators_of_compromise": iocs_payload,
        "cross_source_correlations": correlations_payload,
        "chronological_timeline": timeline_payload,
        "network_flows": flows_payload,
    }

    # Persist JSON file
    filename = f"{inv.id}_report.json"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=_json_serial)

    # Record or update in reports table
    existing_rep = db.query(Report).filter(
        Report.investigation_id == inv.id,
        Report.report_type == "JSON",
    ).first()
    if not existing_rep:
        db_rep = Report(
            investigation_id=inv.id,
            report_type="JSON",
            filename=filename,
            file_path=str(filepath),
            created_at=utc_now(),
        )
        db.add(db_rep)
    else:
        existing_rep.created_at = utc_now()
        existing_rep.file_path = str(filepath)
    db.commit()

    return report_data


def generate_html_report(db: Session, investigation_id: str) -> str:
    """Generates and persists a self-contained HTML forensic dossier.

    Args:
        db: SQLAlchemy database session.
        investigation_id: Unique investigation identifier (e.g., INV-0001).

    Returns:
        Absolute file path string of the generated HTML report.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation '{investigation_id}' not found.")

    severity_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#10b981",
    }
    sev_color = severity_colors.get(inv.severity, "#00e5ff")

    # Render detections rows
    detections_html = ""
    for d in inv.detections:
        badge_cls = d.severity.lower()
        detections_html += f"""
        <tr>
            <td><span class="badge {badge_cls}">{d.severity}</span></td>
            <td><strong>{d.detection_type}</strong></td>
            <td><code>{d.source or '-'}</code></td>
            <td><code>{d.destination or '-'}</code></td>
            <td>{d.evidence}</td>
            <td>+{d.points:.0f} pts</td>
        </tr>"""
    if not detections_html:
        detections_html = "<tr><td colspan='6' class='empty-row'>No threat detections triggered.</td></tr>"

    # Render IOCs rows
    iocs_html = ""
    for i in inv.iocs:
        iocs_html += f"""
        <tr>
            <td><code>{i.type}</code></td>
            <td><strong>{i.canonical_value}</strong></td>
            <td>{i.source}</td>
            <td><span class="badge {i.confidence.lower()}">{i.confidence}</span></td>
            <td>{i.classification or '-'}</td>
        </tr>"""
    if not iocs_html:
        iocs_html = "<tr><td colspan='5' class='empty-row'>No indicators extracted.</td></tr>"

    # Render Correlations rows
    correlations_html = ""
    for c in inv.correlations:
        time_info = f"{c.time_delta_seconds:.1f}s offset" if c.time_delta_seconds is not None else "Cross-vector"
        correlations_html += f"""
        <tr>
            <td><strong>{c.correlation_type}</strong></td>
            <td><code>{c.ioc_value}</code></td>
            <td>{c.source_a} &harr; {c.source_b}</td>
            <td>{c.evidence}</td>
            <td>{time_info}</td>
            <td>+{c.points:.0f} pts</td>
        </tr>"""
    if not correlations_html:
        correlations_html = "<tr><td colspan='6' class='empty-row'>No cross-source correlations identified.</td></tr>"

    # Render Timeline rows
    timeline_html = ""
    sorted_events = sorted(inv.timeline_events, key=lambda x: x.timestamp or utc_now())
    for t in sorted_events:
        ts_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if t.timestamp else "N/A"
        timeline_html += f"""
        <div class="timeline-item">
            <div class="timeline-meta">
                <span class="timestamp">{ts_str}</span>
                <span class="event-type">{t.event_type}</span>
            </div>
            <div class="timeline-body">
                <h4>{t.title}</h4>
                <p>{t.details or ''}</p>
                {f'<div class="ioc-tag">IOC: <code>{t.ioc_value}</code></div>' if t.ioc_value else ''}
            </div>
        </div>"""
    if not timeline_html:
        timeline_html = "<p class='empty-row'>No timeline events recorded.</p>"

    # Render Recommendations
    recs_html = ""
    for rec in (inv.recommendations_json or []):
        recs_html += f"<li>{rec}</li>"
    if not recs_html:
        recs_html = "<li>Maintain continuous telemetry monitoring on target network segment.</li>"

    # Render Analyses Summary
    analyses_html = ""
    for a in inv.analyses:
        analyses_html += f"""
        <div class="analysis-card">
            <div class="analysis-header">
                <span class="badge {a.severity.lower()}">{a.severity}</span>
                <span class="analysis-type">{a.analysis_type}</span>
                <span class="analysis-score">Risk: {a.risk_score:.1f}/100</span>
            </div>
            <div class="analysis-target"><code>{a.target}</code></div>
            <div class="analysis-summary">{a.summary or 'Automated heuristic assessment completed.'}</div>
        </div>"""
    if not analyses_html:
        analyses_html = "<p class='empty-row'>No linked analyses.</p>"

    gen_time = utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{APP_NAME} Forensic Dossier &mdash; {inv.id}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-cyan: #00e5ff;
            --accent-blue: #3b82f6;
            --border: #334155;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #10b981;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            padding: 30px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .brand-logo {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 2px;
            color: var(--accent-cyan);
        }}
        .brand-subtitle {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .header-meta {{ text-align: right; font-size: 13px; color: var(--text-secondary); }}
        .header-meta strong {{ color: var(--text-primary); }}
        .summary-banner {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 24px;
        }}
        .risk-gauge-card {{
            text-align: center;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            border-top: 4px solid {sev_color};
        }}
        .risk-score-value {{
            font-size: 54px;
            font-weight: 900;
            color: {sev_color};
            line-height: 1;
            margin: 10px 0;
        }}
        .risk-severity-tag {{
            font-size: 14px;
            font-weight: 700;
            padding: 4px 12px;
            border-radius: 4px;
            background: {sev_color}22;
            color: {sev_color};
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        h2.section-title {{
            font-size: 18px;
            font-weight: 700;
            color: var(--accent-cyan);
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        p.explanation {{
            color: var(--text-secondary);
            margin-bottom: 15px;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}
        code {{
            background: rgba(0, 229, 255, 0.1);
            color: var(--accent-cyan);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 12px;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge.low {{ background: rgba(16, 185, 129, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .analyses-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }}
        .analysis-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
        }}
        .analysis-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .analysis-type {{ font-weight: 700; color: var(--accent-blue); font-size: 12px; }}
        .analysis-score {{ font-size: 12px; color: var(--text-secondary); }}
        .analysis-target {{ word-break: break-all; margin-bottom: 8px; }}
        .analysis-summary {{ font-size: 13px; color: var(--text-secondary); }}
        .timeline-container {{
            border-left: 2px solid var(--border);
            margin-left: 10px;
            padding-left: 20px;
        }}
        .timeline-item {{
            margin-bottom: 20px;
            position: relative;
        }}
        .timeline-item::before {{
            content: "";
            position: absolute;
            left: -27px;
            top: 4px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--accent-cyan);
            border: 2px solid var(--bg-primary);
        }}
        .timeline-meta {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }}
        .timeline-meta .timestamp {{ margin-right: 12px; font-weight: 600; color: var(--accent-cyan); }}
        .timeline-body h4 {{ font-size: 14px; margin-bottom: 4px; }}
        .timeline-body p {{ font-size: 13px; color: var(--text-secondary); }}
        .ioc-tag {{ margin-top: 4px; }}
        ul.recs-list {{
            list-style-type: none;
            padding: 0;
        }}
        ul.recs-list li {{
            background: var(--bg-card);
            border-left: 3px solid var(--accent-cyan);
            padding: 12px 16px;
            margin-bottom: 10px;
            font-size: 13px;
            border-radius: 0 4px 4px 0;
        }}
        .empty-row {{ text-align: center; color: var(--text-secondary); padding: 20px; }}
        footer {{
            margin-top: 40px;
            border-top: 1px solid var(--border);
            padding-top: 20px;
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand-logo">{APP_NAME}</div>
                <div class="brand-subtitle">Network Threat &amp; Phishing Analysis Platform</div>
            </div>
            <div class="header-meta">
                <div>Forensic Dossier: <strong>{inv.id}</strong></div>
                <div>Generated: <strong>{gen_time}</strong></div>
                <div>Security Lead: <strong>{AUTHOR}</strong></div>
            </div>
        </header>

        <section class="summary-banner">
            <div class="card">
                <h2 class="section-title">Case Overview: {inv.title}</h2>
                <p class="explanation">{inv.explanation or 'Comprehensive multi-source analysis evaluating offline URL lexical heuristics and Scapy-parsed PCAP network flow behaviors.'}</p>
                <div style="font-size: 13px; color: var(--text-secondary); margin-top: 10px;">
                    <span>Status: <strong style="color: var(--text-primary);">{inv.status}</strong></span> &bull;
                    <span style="margin-left: 10px;">Linked Analyses: <strong style="color: var(--text-primary);">{len(inv.analyses)}</strong></span> &bull;
                    <span style="margin-left: 10px;">Detections: <strong style="color: var(--text-primary);">{len(inv.detections)}</strong></span> &bull;
                    <span style="margin-left: 10px;">Correlations: <strong style="color: var(--text-primary);">{len(inv.correlations)}</strong></span>
                </div>
            </div>
            <div class="card risk-gauge-card">
                <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-secondary);">Composite Threat Score</div>
                <div class="risk-score-value">{inv.risk_score:.0f}</div>
                <div class="risk-severity-tag">{inv.severity} Posture</div>
            </div>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Linked Forensic Analyses</h2>
            <div class="analyses-grid">
                {analyses_html}
            </div>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Deterministic Threat Detections</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Detection Rule</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Evidence / Forensic Findings</th>
                        <th>Weight</th>
                    </tr>
                </thead>
                <tbody>
                    {detections_html}
                </tbody>
            </table>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Cross-Source &amp; Temporal Correlation Evidence</h2>
            <table>
                <thead>
                    <tr>
                        <th>Correlation Type</th>
                        <th>Pivot IOC</th>
                        <th>Correlated Vectors</th>
                        <th>Evidence Synthesis</th>
                        <th>Time Alignment</th>
                        <th>Score Contribution</th>
                    </tr>
                </thead>
                <tbody>
                    {correlations_html}
                </tbody>
            </table>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Indicators of Compromise (Normalized Intelligence)</h2>
            <table>
                <thead>
                    <tr>
                        <th>IOC Type</th>
                        <th>Canonical Value</th>
                        <th>Provenance Vector</th>
                        <th>Confidence</th>
                        <th>Scope / Classification</th>
                    </tr>
                </thead>
                <tbody>
                    {iocs_html}
                </tbody>
            </table>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Chronological Event Timeline</h2>
            <div class="timeline-container">
                {timeline_html}
            </div>
        </section>

        <section class="card" style="margin-bottom: 30px;">
            <h2 class="section-title">Defensive Mitigation &amp; Remediation Plan</h2>
            <ul class="recs-list">
                {recs_html}
            </ul>
        </section>

        <footer>
            <div>Platform: {APP_NAME} v{APP_VERSION} &bull; Deterministic Security Engineering Architecture</div>
            <div>Author: {AUTHOR}</div>
        </footer>
    </div>
</body>
</html>
"""

    # Persist HTML file
    filename = f"{inv.id}_report.html"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Record or update in reports table
    existing_rep = db.query(Report).filter(
        Report.investigation_id == inv.id,
        Report.report_type == "HTML",
    ).first()
    if not existing_rep:
        db_rep = Report(
            investigation_id=inv.id,
            report_type="HTML",
            filename=filename,
            file_path=str(filepath),
            created_at=utc_now(),
        )
        db.add(db_rep)
    else:
        existing_rep.created_at = utc_now()
        existing_rep.file_path = str(filepath)
    db.commit()

    return str(filepath)
