"""Deterministic URL phishing detection and explainable risk scoring rules.

Author: Hrudyansh Kayastha
"""

from typing import Dict, Any, List, Tuple


def evaluate_url_detections(parsed_url: Dict[str, Any], features: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], float, str]:
    """Evaluates static security features and generates explainable detections, factors, and score."""
    detections: List[Dict[str, Any]] = []
    factors: List[Dict[str, Any]] = []

    raw_url = parsed_url.get("raw_url", "")
    hostname = parsed_url.get("hostname", "")

    # 1. IP Hostname (+20)
    if features.get("is_ipv4_host") or features.get("is_ip_host"):
        pts = 20.0
        reason = f"Hostname uses direct IPv4 address '{hostname}'"
        detections.append({
            "detection_type": "Direct IP-Based Hostname (Raw IP)",
            "source": hostname,
            "destination": None,
            "evidence": f"Target host '{hostname}' bypasses standard DNS registration hierarchy",
            "severity": "HIGH",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "IP hostname", "points": pts, "reason": reason})

    # 2. HTTP Transport (+15)
    if features.get("is_http"):
        pts = 15.0
        reason = "URL uses unencrypted HTTP instead of HTTPS"
        detections.append({
            "detection_type": "Unencrypted HTTP Scheme",
            "source": raw_url,
            "destination": hostname,
            "evidence": "Transport scheme is unencrypted plaintext 'http://'",
            "severity": "MEDIUM",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "HTTP instead of HTTPS", "points": pts, "reason": reason})

    # 3. Punycode / IDN (+15)
    if features.get("is_punycode"):
        pts = 15.0
        reason = f"Hostname contains Punycode prefix 'xn--' in '{hostname}'"
        detections.append({
            "detection_type": "Punycode (IDN) Hostname",
            "source": hostname,
            "destination": None,
            "evidence": f"Internationalized domain prefix detected in host: {hostname}",
            "severity": "HIGH",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "Punycode / IDN", "points": pts, "reason": reason})

    # 4. Suspicious Keywords (+10)
    kws = features.get("suspicious_keywords_found", [])
    if kws:
        pts = 10.0
        kw_str = ", ".join(kws[:4])
        reason = f"URL path/query contains credential lure keywords: [{kw_str}]"
        detections.append({
            "detection_type": "Suspicious Keyword Lure",
            "source": raw_url,
            "destination": hostname,
            "evidence": f"Lure keywords observed in URI components: {kw_str}",
            "severity": "MEDIUM",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "Suspicious keyword", "points": pts, "reason": reason})

    # 5. URL Shortener (+10)
    if features.get("is_shortener"):
        pts = 10.0
        reason = f"Domain matches known URL shortening service '{hostname}'"
        detections.append({
            "detection_type": "URL Shortener Redirection",
            "source": hostname,
            "destination": None,
            "evidence": f"Shortener service obfuscates target destination: {hostname}",
            "severity": "MEDIUM",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "URL shortener", "points": pts, "reason": reason})

    # 6. Excessive Subdomains (+10)
    if features.get("subdomain_count", 0) >= 3 or parsed_url.get("hostname_depth", 1) >= 4:
        pts = 10.0
        depth = features.get("subdomain_count", 0)
        reason = f"Subdomain chain depth ({depth}) is excessively deep"
        detections.append({
            "detection_type": "Excessive Subdomain Depth",
            "source": parsed_url.get("subdomain", ""),
            "destination": hostname,
            "evidence": f"Nested subdomain chain contains {depth} hierarchical labels",
            "severity": "MEDIUM",
            "confidence": "medium",
            "points": pts,
        })
        factors.append({"name": "Excessive subdomains", "points": pts, "reason": reason})

    # 7. Suspicious TLD (+10)
    if features.get("is_suspicious_tld"):
        pts = 10.0
        tld_val = parsed_url.get("tld", "")
        reason = f"Top-level domain '.{tld_val}' is classified as high-risk"
        detections.append({
            "detection_type": "High-Risk TLD",
            "source": hostname,
            "destination": None,
            "evidence": f"TLD '.{tld_val}' is statistically associated with disposable phishing campaigns",
            "severity": "MEDIUM",
            "confidence": "medium",
            "points": pts,
        })
        factors.append({"name": "Suspicious TLD", "points": pts, "reason": reason})

    # 8. @ Symbol Obfuscation (+10)
    if features.get("has_at_symbol"):
        pts = 10.0
        reason = "URL contains @ symbol credential authority delimiter"
        detections.append({
            "detection_type": "@ Symbol Obfuscation",
            "source": raw_url,
            "destination": hostname,
            "evidence": "User authentication authority delimiter '@' hides actual destination hostname",
            "severity": "HIGH",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "@ symbol delimiter", "points": pts, "reason": reason})

    # 9. Repeated Separators in Path / Host (+10)
    if features.get("has_suspicious_structure"):
        pts = 10.0
        reason = "URL contains multiple slashes or repeated hyphens"
        detections.append({
            "detection_type": "Repeated Separator Pattern",
            "source": raw_url,
            "destination": hostname,
            "evidence": "Observed repeated directory separators or hyphens designed to confuse parsers",
            "severity": "MEDIUM",
            "confidence": "high",
            "points": pts,
        })
        factors.append({"name": "Repeated separators", "points": pts, "reason": reason})

    # 10. Special Characters (+10)
    if features.get("has_excessive_special_chars"):
        pts = 10.0
        density = features.get("special_char_density", 0.0)
        reason = f"Special character density is unusually high ({density:.1%})"
        detections.append({
            "detection_type": "High Special Character Density",
            "source": raw_url,
            "destination": None,
            "evidence": f"High ratio of punctuation and tracking parameters: {density:.1%}",
            "severity": "LOW",
            "confidence": "medium",
            "points": pts,
        })
        factors.append({"name": "Special characters", "points": pts, "reason": reason})

    # 11. Encoded Path (+5)
    if features.get("has_excessive_encoding"):
        pts = 5.0
        enc_count = features.get("encoded_char_count", 0)
        reason = f"Target contains {enc_count} percent-encoded sequences"
        detections.append({
            "detection_type": "Obfuscated Percent-Encoding",
            "source": raw_url,
            "destination": None,
            "evidence": f"Observed {enc_count} percent-encoded tokens in URI path/query",
            "severity": "LOW",
            "confidence": "medium",
            "points": pts,
        })
        factors.append({"name": "Encoded path", "points": pts, "reason": reason})

    # 12. Brand Mismatch (+10)
    if features.get("has_brand_mismatch"):
        pts = 10.0
        brands = ", ".join(features.get("mismatched_brands", []))
        reason = f"Trusted brand '{brands}' appears in URI path but not registered domain"
        detections.append({
            "detection_type": "Brand Name Mismatch",
            "source": raw_url,
            "destination": hostname,
            "evidence": f"Brand token '{brands}' injected into path while host is '{parsed_url.get('registered_domain')}'",
            "severity": "MEDIUM",
            "confidence": "medium",
            "points": pts,
        })
        factors.append({"name": "Brand / Hostname mismatch", "points": pts, "reason": reason})

    # Calculate Total Score (Capped at 100)
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
