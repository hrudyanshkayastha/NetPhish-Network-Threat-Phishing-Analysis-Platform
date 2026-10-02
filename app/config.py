"""Configuration and detection thresholds for NetPhish.

Author: Hrudyansh Kayastha
"""

import os
from pathlib import Path
from typing import Set, List

# Core Directory Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLES_DIR = BASE_DIR / "samples"
UI_STATIC_DIR = BASE_DIR / "app" / "ui" / "static"
UI_TEMPLATES_DIR = BASE_DIR / "app" / "ui" / "templates"

DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = os.getenv("NETPHISH_DB_PATH", str(DATA_DIR / "netphish.db"))

# Application Metadata
APP_NAME = "NETPHISH"
APP_DESCRIPTION = "Network Threat & Phishing Analysis Platform"
APP_VERSION = "2.0.0"
AUTHOR = "Hrudyansh Kayastha"

# File Upload Limits (Max: 25 MB)
MAX_UPLOAD_SIZE_BYTES = 25 * 1024 * 1024
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# Common Legitimate Service Destination Ports
COMMON_PORTS: Set[int] = {
    20, 21,    # FTP
    22,        # SSH
    23,        # Telnet
    25,        # SMTP
    53,        # DNS
    80,        # HTTP
    110,       # POP3
    123,       # NTP
    143,       # IMAP
    443,       # HTTPS
    445,       # SMB
    587,       # SMTPS
    993,       # IMAPS
    995,       # POP3S
    3306,      # MySQL
    3389,      # RDP
    5432,      # PostgreSQL
    8080,      # HTTP-Alt
    8443,      # HTTPS-Alt
}

# Suspicious Credential & Authentication Lure Keywords
SUSPICIOUS_KEYWORDS: List[str] = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "signin",
    "bank",
    "wallet",
    "payment",
    "confirm",
    "authenticate",
    "support",
    "billing",
    "recover",
    "security",
    "alert",
    "access",
    "validate",
    "portal",
    "authorize",
]

# Public URL Shortener Domains
SHORTENER_DOMAINS: Set[str] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "tiny.cc",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
    "goo.gl",
    "adf.ly",
    "bc.vc",
}

# High-Risk / Abused TLDs
SUSPICIOUS_TLDS: Set[str] = {
    "xyz",
    "top",
    "work",
    "loan",
    "click",
    "fit",
    "surf",
    "rest",
    "gq",
    "ml",
    "cf",
    "tk",
    "ga",
    "buzz",
    "icu",
    "monster",
    "hair",
    "beauty",
}

# Trusted Brand Names (for Brand / Host Mismatch Heuristics)
TRUSTED_BRAND_KEYWORDS: List[str] = [
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "bankofamerica",
    "wellsfargo",
    "chase",
    "citibank",
    "facebook",
    "instagram",
    "meta",
    "dropbox",
    "github",
]

# Network Threat Detection Thresholds
PORT_SCAN_THRESHOLD: int = 10                  # Unique destination ports targeted
PORT_SCAN_WINDOW_SEC: float = 60.0             # Sliding window in seconds

HIGH_CONNECTION_RATE_THRESHOLD: int = 50       # Packets/connections in window
HIGH_CONNECTION_RATE_WINDOW_SEC: float = 10.0  # Sliding window in seconds

BEACONING_MIN_CONNECTIONS: int = 4             # Minimum repeated connections
BEACONING_MAX_VARIANCE_COEFF: float = 0.35     # Coefficient of variation (sigma / mu <= 0.35)

ICMP_BURST_THRESHOLD: int = 20                 # ICMP packets in window
ICMP_BURST_WINDOW_SEC: float = 10.0            # Window in seconds

DNS_ANOMALY_DOMAIN_LENGTH: int = 50            # Domain character length considered anomalous
DNS_ANOMALY_SUBDOMAIN_DEPTH: int = 4           # Subdomain depth threshold
DNS_ANOMALY_NUMERIC_RATIO: float = 0.40        # Ratio of digits in hostname label

# Temporal Correlation Window (Default: +/- 5 minutes)
TEMPORAL_WINDOW_SECONDS: float = 300.0
