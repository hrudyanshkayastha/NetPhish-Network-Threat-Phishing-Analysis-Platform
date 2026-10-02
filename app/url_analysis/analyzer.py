"""High-level static URL analysis coordinator."""

from typing import Dict, Any
from app.url_analysis.parser import parse_url
from app.url_analysis.features import extract_url_features
from app.url_analysis.detector import evaluate_url_detections
from app.ioc.extractor import extract_iocs_from_url_data


def analyze_url_target(url_target: str) -> Dict[str, Any]:
    """
    Coordinates static URL analysis completely offline.
    Never sends network requests or makes socket calls.
    """
    # 1. Lexical parsing & domain decomposition
    parsed_info = parse_url(url_target)

    # 2. Extract 15 security features
    features = extract_url_features(parsed_info)

    # 3. Evaluate deterministic detection rules & risk score
    detections, factors, risk_score, severity = evaluate_url_detections(parsed_info, features)

    # 4. Generate summary narrative
    if risk_score >= 60.0:
        summary = f"High-risk potential phishing indicators identified ({len(detections)} detection rules triggered)."
    elif risk_score >= 30.0:
        summary = f"Suspicious characteristics observed ({len(detections)} detection rules triggered). Requires analyst review."
    else:
        summary = "Standard lexical profile. No significant deceptive phishing patterns detected."

    # 5. Extract normalized IOCs
    iocs = extract_iocs_from_url_data(parsed_info, risk_score, severity)

    return {
        "target": parsed_info["raw_url"],
        "canonical_url": parsed_info["canonical_url"],
        "status": "COMPLETED",
        "risk_score": risk_score,
        "severity": severity,
        "summary": summary,
        "parsed": parsed_info,
        "features": features,
        "factors": factors,
        "detections": detections,
        "iocs": iocs,
    }
