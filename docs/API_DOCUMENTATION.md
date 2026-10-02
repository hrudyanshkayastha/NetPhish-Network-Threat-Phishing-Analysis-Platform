# NetPhish REST API Interface Specification

**Author:** Hrudyansh Kayastha  
**Version:** 2.0.0  
**Base URL:** `http://127.0.0.1:8000/api`  

---

## 1. System Health & Operational Telemetry

### `GET /api/health`
Retrieves operational status of the NetPhish platform and loaded detection subsystems.

- **Response:** `200 OK`
```json
{
  "status": "healthy",
  "app_name": "NETPHISH",
  "version": "2.0.0",
  "author": "Hrudyansh Kayastha",
  "timestamp": "2026-10-02T15:00:00Z",
  "modules": {
    "url_analyzer": "operational",
    "pcap_analyzer": "operational",
    "ioc_intelligence": "operational",
    "correlation_engine": "operational",
    "risk_scoring": "operational",
    "investigation_management": "operational",
    "forensic_reporting": "operational"
  }
}
```

---

### `GET /api/stats`
Retrieves aggregated platform metrics across triage runs, detections, IOC inventory, and active investigation dossiers.

- **Response:** `200 OK`
```json
{
  "total_analyses": 24,
  "url_analyses": 14,
  "pcap_analyses": 10,
  "total_detections": 42,
  "critical_detections": 8,
  "total_iocs": 89,
  "active_investigations": 5,
  "max_risk_score": 92.5
}
```

---

## 2. Threat Analysis Endpoints

### `POST /api/url/analyze`
Performs deterministic offline static lexical analysis on a target URL without network transmission.

- **Request Body:** `application/json`
```json
{
  "url": "http://203.0.113.50:8080/secure-update/login.php?client=admin"
}
```

- **Response:** `200 OK`
```json
{
  "id": 1,
  "target": "http://203.0.113.50:8080/secure-update/login.php?client=admin",
  "status": "COMPLETED",
  "risk_score": 75.0,
  "severity": "HIGH",
  "summary": "High-risk potential phishing indicators identified (4 detection rules triggered).",
  "features": {
    "is_https": false,
    "is_ipv4_host": true,
    "url_length": 62,
    "subdomain_count": 0,
    "has_at_symbol": false,
    "suspicious_keywords_found": ["login", "secure", "update"],
    "is_shortener": false,
    "is_punycode": false,
    "is_suspicious_tld": false,
    "special_char_density": 0.145,
    "path_depth": 2,
    "has_suspicious_structure": false,
    "has_brand_mismatch": false
  },
  "factors": [
    {
      "name": "IP hostname",
      "points": 20.0,
      "reason": "Hostname uses direct IPv4 address '203.0.113.50'"
    },
    {
      "name": "HTTP instead of HTTPS",
      "points": 15.0,
      "reason": "URL uses unencrypted HTTP instead of HTTPS"
    }
  ],
  "detections": [
    {
      "id": 1,
      "detection_type": "Direct IP-Based Hostname (Raw IP)",
      "source": "203.0.113.50",
      "destination": null,
      "evidence": "Target host '203.0.113.50' bypasses standard DNS registration hierarchy",
      "severity": "HIGH",
      "confidence": "high",
      "points": 20.0
    }
  ],
  "iocs": [
    {
      "id": 1,
      "type": "URL",
      "canonical_value": "http://203.0.113.50:8080/secure-update/login.php?client=admin",
      "source": "URL_ANALYSIS",
      "confidence": "high",
      "classification": "Risk Rating: HIGH (75/100)"
    }
  ]
}
```

---

### `POST /api/pcap/analyze`
Uploads and parses an offline `.pcap` or `.pcapng` capture file using Scapy. Reconstructs 5-tuple flows, computes SHA-256 integrity hash, and executes behavioral threat heuristics.

- **Request Body:** `multipart/form-data`
  - `file`: binary capture data (`.pcap`, `.pcapng`, `.cap`) (Max size: 25 MB)

- **Response:** `200 OK`
```json
{
  "id": 2,
  "filename": "sample_scan.pcap",
  "file_hash": "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
  "packet_count": 48,
  "flow_count": 14,
  "duration_seconds": 12.4,
  "risk_score": 65.0,
  "severity": "HIGH",
  "summary": "Suspicious network activity detected (2 detection rules triggered). Requires further triage.",
  "protocols": { "TCP": 48 },
  "flows": [
    {
      "id": 1,
      "src_ip": "10.0.0.5",
      "dst_ip": "10.0.0.1",
      "src_port": 51234,
      "dst_port": 22,
      "protocol": "TCP",
      "packet_count": 4,
      "byte_count": 240,
      "duration": 0.05,
      "tcp_flags": "SYN"
    }
  ],
  "detections": [
    {
      "id": 2,
      "detection_type": "Possible Port Scan",
      "source": "10.0.0.5",
      "destination": "10.0.0.1",
      "evidence": "Source host 10.0.0.5 probed 14 unique destination ports on target 10.0.0.1",
      "severity": "HIGH",
      "confidence": "high",
      "points": 20.0
    }
  ],
  "iocs": [
    {
      "id": 2,
      "type": "IPv4",
      "canonical_value": "10.0.0.5",
      "source": "PCAP_FLOW",
      "confidence": "high",
      "classification": "Private (RFC 1918 / ULA) (Source Host)"
    }
  ]
}
```

---

## 3. Investigation Dossiers & Forensics

### `POST /api/investigations`
Creates a consolidated investigation dossier linking multiple URL and PCAP analyses, executing cross-source correlation and calculating composite risk score.

- **Request Body:** `application/json`
```json
{
  "title": "Phishing Lure & Host Probe Investigation",
  "analysis_ids": [1, 2],
  "explanation": "Correlating incoming credential harvest attempt with outbound network scans"
}
```

- **Response:** `200 OK` (Investigation dossier detailing linked analyses, detections, correlations, timeline, and remediation plan)

---

### `GET /api/investigations/{id}`
Retrieves complete forensic dossier for a specific investigation (e.g. `INV-0001`).

---

### `GET /api/reports/{id}/json`
Exports standardized JSON forensic dossier for incident reporting and SIEM ingestion.

---

### `GET /api/reports/{id}/html`
Renders standalone, responsive HTML forensic dossier with complete evidence tables and remediation recommendations.

---

## 4. IOC Threat Intelligence

### `GET /api/iocs`
Retrieves paginated normalized Indicators of Compromise.
- **Query Parameters:**
  - `ioc_type`: Filter by type (`IPv4`, `DOMAIN`, `URL`, `HASH`, `EMAIL`)
  - `source`: Filter by origin (`URL_ANALYSIS`, `PCAP_FLOW`, `DNS_QUERY`, `HTTP_METADATA`)
  - `confidence`: Filter by confidence (`high`, `medium`, `low`)
  - `search`: Substring search on canonical value
  - `limit`: Number of results (default: 100)
  - `offset`: Pagination offset (default: 0)

---

## 5. Sample Testing

### `GET /api/samples`
Lists available synthetic captures and verification URLs bundled in `samples/` for rapid platform testing.
