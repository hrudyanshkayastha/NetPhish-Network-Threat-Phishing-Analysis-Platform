# NETPHISH — Network Threat & Phishing Analysis Platform

**Author:** Hrudyansh Kayastha  
**Version:** 2.0.0  
**License:** MIT  

---

## Overview

NetPhish is a professional defensive cybersecurity engineering platform designed for offline static URL triage, Scapy-powered PCAP network flow reconstruction, and multi-source evidence correlation. By analyzing artifacts locally and deterministically, NetPhish enables security analysts to correlate deceptive phishing indicators with suspicious network traffic without transmitting packets or generating outbound HTTP requests.

---

## Core Security Capabilities

- **Zero-Network Static URL Triage:** Analyzes 15 lexical and structural security features including raw IPv4 hosts, brand/host mismatches, high-risk TLDs, Punycode (IDN), @ symbol obfuscation, and credential lure keywords.
- **Offline PCAP Flow Dissection:** Ingests `.pcap` and `.pcapng` capture files, reconstructs bidirectional 5-tuple logical connection flows `(src_ip, dst_ip, src_port, dst_port, protocol)`, and computes SHA-256 capture hashes.
- **Behavioral Threat Heuristics:** Detects horizontal/vertical port scans (≥10 unique ports), connection rate bursts (≥50 conns/10s), periodic C2 beaconing ($CV \le 0.35$), ICMP flood sweeps, non-standard destination ports, and DNS length/depth anomalies.
- **Normalized IOC Intelligence:** Canonicalizes indicators across disparate sources and strictly classifies IPv4 scopes (RFC 1918 Private, RFC 5737 Documentation/Test-Net, Loopback, Public).
- **Cross-Source & Temporal Correlation:** Evaluates shared indicators between URL artifacts and PCAP flows within a configurable sliding window ($\pm 5$ minutes).
- **Explainable Unified Risk Scoring:** Transparent composite scoring capped at 100 with itemized contributing factor attribution (URL: 40, PCAP: 40, IOC Correlation: 15, Temporal: 15).
- **Forensic Investigation Dossiers:** Assembles formal investigation cases (`INV-xxxx`), chronological incident timelines, defensive mitigation playbooks, and exportable JSON/HTML reports.

---

## Quick Start

### Installation

```bash
git clone <repository-url>
cd netphish
pip install -r requirements.txt
```

### Starting the SOC Platform

```bash
python run.py
```

Access the local SOC Investigation Dashboard at `http://127.0.0.1:8000` or view the interactive OpenAPI specification at `http://127.0.0.1:8000/docs`.

### Running the Test Suite

```bash
pytest tests -v
```
