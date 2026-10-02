"""Static security feature extraction engine for URLs.

Author: Hrudyansh Kayastha
"""

import re
from typing import Dict, Any, List

from app.config import (
    SUSPICIOUS_KEYWORDS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    TRUSTED_BRAND_KEYWORDS,
)


def extract_url_features(parsed_url: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts 15 deterministic lexical and structural security features from parsed URL data."""
    raw_url = parsed_url.get("raw_url", "")
    scheme = parsed_url.get("scheme", "").lower()
    hostname = parsed_url.get("hostname", "").lower()
    path = parsed_url.get("path", "")
    query = parsed_url.get("query", "")
    registered_domain = parsed_url.get("registered_domain", "").lower()
    subdomain = parsed_url.get("subdomain", "").lower()
    tld = parsed_url.get("tld", "").lower()
    is_ipv4 = parsed_url.get("is_ipv4", False) or parsed_url.get("is_ip_host", False)

    # 1. Scheme checks
    is_https = scheme == "https"
    is_http = scheme == "http"

    # 2. Lengths
    url_length = len(raw_url)
    hostname_length = len(hostname)

    # 3. Subdomain count
    subdomain_parts = [p for p in subdomain.split(".") if p]
    subdomain_count = len(subdomain_parts)

    # 4. @ symbol
    has_at_symbol = "@" in raw_url or bool(parsed_url.get("username"))

    # 5. Suspicious keywords
    target_text = f"{subdomain} {path} {query}".lower()
    detected_keywords: List[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in target_text:
            detected_keywords.append(kw)

    # 6. Shortener check
    is_shortener = False
    for s in SHORTENER_DOMAINS:
        if hostname == s or hostname.endswith(f".{s}"):
            is_shortener = True
            break

    # 7. Punycode check
    is_punycode = "xn--" in hostname

    # 8. Suspicious TLD
    clean_tld = tld.split(".")[-1] if tld else ""
    is_suspicious_tld = clean_tld in SUSPICIOUS_TLDS

    # 9. Special character density
    special_chars = set("-_@%?&=+~#$;:,")
    spec_count = sum(1 for c in raw_url if c in special_chars)
    special_density = spec_count / url_length if url_length > 0 else 0.0
    has_excessive_special = special_density > 0.15 or spec_count > 10

    # 10. Encoded characters
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    encoded_count = len(encoded_matches)
    has_excessive_encoding = encoded_count >= 3 or "%2f" in raw_url.lower() or "%2e" in raw_url.lower()

    # 11. Path depth
    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)

    # 12. Suspicious structure (repeated slashes, hyphens, excessive dots)
    has_multiple_slashes = bool(re.search(r"[^:]//+", raw_url))
    has_repeated_hyphens = "--" in hostname or "--" in path
    has_repeated_dots = ".." in raw_url
    has_suspicious_structure = has_multiple_slashes or has_repeated_hyphens or has_repeated_dots

    # 13. Brand / Hostname mismatch
    mismatched_brands: List[str] = []
    for brand in TRUSTED_BRAND_KEYWORDS:
        if brand in target_text and brand not in registered_domain:
            mismatched_brands.append(brand)
    has_brand_mismatch = len(mismatched_brands) > 0

    return {
        "is_https": is_https,
        "has_https": is_https,
        "is_http": is_http,
        "is_ipv4_host": is_ipv4,
        "is_ip_host": is_ipv4,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "subdomain_count": subdomain_count,
        "has_at_symbol": has_at_symbol,
        "suspicious_keywords_found": sorted(list(set(detected_keywords))),
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
        "is_suspicious_tld": is_suspicious_tld,
        "special_char_density": round(special_density, 3),
        "has_excessive_special_chars": has_excessive_special,
        "encoded_char_count": encoded_count,
        "has_excessive_encoding": has_excessive_encoding,
        "path_depth": path_depth,
        "has_suspicious_structure": has_suspicious_structure,
        "has_brand_mismatch": has_brand_mismatch,
        "mismatched_brands": mismatched_brands,
    }
