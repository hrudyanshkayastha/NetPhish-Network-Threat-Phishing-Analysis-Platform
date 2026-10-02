"""Synthetic sample dataset generator using Scapy.

Generates 100% deterministic, benign, and safe PCAP files demonstrating:
1. Normal clean browsing
2. Phishing host HTTP connection and DNS query
3. TCP Port scan behavior (15 distinct ports)
4. Periodic C2 beaconing pattern (regular 3-second intervals)
5. DNS anomaly (excessively long domain with deep subdomain structure)
6. Malformed capture file for parser error testing
"""

import os
import time
from pathlib import Path
from scapy.all import (
    wrpcap,
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
)

BASE_DIR = Path(__file__).resolve().parent
BASE_DIR.mkdir(parents=True, exist_ok=True)


def create_sample_clean():
    """Generates benign web browsing traffic (DNS query + HTTPS handshake)."""
    pkts = []
    base_time = 1710000000.0  # Deterministic reference epoch

    # 1. DNS query for example.com
    dns_req = (
        IP(src="192.168.1.50", dst="1.1.1.1") /
        UDP(sport=53120, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_req.time = base_time
    pkts.append(dns_req)

    # 2. DNS response
    dns_resp = (
        IP(src="1.1.1.1", dst="192.168.1.50") /
        UDP(sport=53, dport=53120) /
        DNS(qr=1, aa=1, qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300))
    )
    dns_resp.time = base_time + 0.035
    pkts.append(dns_resp)

    # 3. HTTPS TCP 3-way handshake to 93.184.216.34:443
    syn = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="S", seq=1000)
    syn.time = base_time + 0.050
    pkts.append(syn)

    syn_ack = IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=443, dport=49152, flags="SA", seq=2000, ack=1001)
    syn_ack.time = base_time + 0.080
    pkts.append(syn_ack)

    ack = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="A", seq=1001, ack=2001)
    ack.time = base_time + 0.085
    pkts.append(ack)

    # Data packets
    data = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="PA", seq=1001, ack=2001) / Raw(b"TLS_CLIENT_HELLO_PLACEHOLDER")
    data.time = base_time + 0.090
    pkts.append(data)

    out_path = BASE_DIR / "sample_clean.pcap"
    wrpcap(str(out_path), pkts)
    print(f"Generated {out_path} ({len(pkts)} packets)")


def create_sample_suspicious():
    """Generates suspicious phishing traffic correlating with http://203.0.113.50/login/verify."""
    pkts = []
    base_time = 1710000000.0

    # 1. DNS query for suspicious domain
    dns_req = (
        IP(src="192.168.1.100", dst="8.8.8.8") /
        UDP(sport=51234, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="secure-banking-verify.xyz", qtype="A"))
    )
    dns_req.time = base_time
    pkts.append(dns_req)

    dns_resp = (
        IP(src="8.8.8.8", dst="192.168.1.100") /
        UDP(sport=53, dport=51234) /
        DNS(qr=1, qd=DNSQR(qname="secure-banking-verify.xyz", qtype="A"),
            an=DNSRR(rrname="secure-banking-verify.xyz", type="A", rdata="203.0.113.50", ttl=60))
    )
    dns_resp.time = base_time + 0.040
    pkts.append(dns_resp)

    # 2. HTTP GET to raw IP host 203.0.113.50/login/verify
    http_payload = (
        b"GET /login/verify HTTP/1.1\r\n"
        b"Host: 203.0.113.50\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html\r\n\r\n"
    )

    syn = IP(src="192.168.1.100", dst="203.0.113.50") / TCP(sport=55100, dport=80, flags="S", seq=5000)
    syn.time = base_time + 0.060
    pkts.append(syn)

    syn_ack = IP(src="203.0.113.50", dst="192.168.1.100") / TCP(sport=80, dport=55100, flags="SA", seq=6000, ack=5001)
    syn_ack.time = base_time + 0.085
    pkts.append(syn_ack)

    ack = IP(src="192.168.1.100", dst="203.0.113.50") / TCP(sport=55100, dport=80, flags="A", seq=5001, ack=6001)
    ack.time = base_time + 0.090
    pkts.append(ack)

    http_pkt = (
        IP(src="192.168.1.100", dst="203.0.113.50") /
        TCP(sport=55100, dport=80, flags="PA", seq=5001, ack=6001) /
        Raw(http_payload)
    )
    http_pkt.time = base_time + 0.095
    pkts.append(http_pkt)

    out_path = BASE_DIR / "sample_suspicious.pcap"
    wrpcap(str(out_path), pkts)
    print(f"Generated {out_path} ({len(pkts)} packets)")


def create_sample_scan():
    """Generates a TCP SYN port scan across 15 destination ports."""
    pkts = []
    base_time = 1710000000.0
    scan_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

    for idx, port in enumerate(scan_ports):
        # TCP SYN probe
        syn = (
            IP(src="192.168.1.105", dst="192.168.1.1") /
            TCP(sport=40000 + idx, dport=port, flags="S", seq=10000 + idx)
        )
        syn.time = base_time + (idx * 0.15)
        pkts.append(syn)

        # RST or closed response from target for some ports
        if port not in (80, 443):
            rst = (
                IP(src="192.168.1.1", dst="192.168.1.105") /
                TCP(sport=port, dport=40000 + idx, flags="RA", seq=0, ack=10001 + idx)
            )
            rst.time = base_time + (idx * 0.15) + 0.02
            pkts.append(rst)

    out_path = BASE_DIR / "sample_scan.pcap"
    wrpcap(str(out_path), pkts)
    print(f"Generated {out_path} ({len(pkts)} packets)")


def create_sample_beacon():
    """Generates periodic repeated connections every 3.0 seconds (low variance)."""
    pkts = []
    base_time = 1710000000.0
    interval = 3.0

    for i in range(8):
        conn_time = base_time + (i * interval)
        syn = (
            IP(src="192.168.1.80", dst="198.51.100.25") /
            TCP(sport=50000 + i, dport=8443, flags="S", seq=20000 + i * 100)
        )
        syn.time = conn_time
        pkts.append(syn)

        ack = (
            IP(src="198.51.100.25", dst="192.168.1.80") /
            TCP(sport=8443, dport=50000 + i, flags="SA", seq=30000, ack=20001 + i * 100)
        )
        ack.time = conn_time + 0.03
        pkts.append(ack)

    out_path = BASE_DIR / "sample_beacon.pcap"
    wrpcap(str(out_path), pkts)
    print(f"Generated {out_path} ({len(pkts)} packets)")


def create_sample_dns_anomaly():
    """Generates DNS query with excessively long domain and deep subdomain structure."""
    pkts = []
    base_time = 1710000000.0

    long_domain = "v1-sec-update-stage9-auth-token-exfil-staging-node492817.phish-domain.xyz"

    for i in range(4):
        req = (
            IP(src="192.168.1.66", dst="8.8.8.8") /
            UDP(sport=54000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=long_domain, qtype="TXT"))
        )
        req.time = base_time + (i * 0.2)
        pkts.append(req)

    out_path = BASE_DIR / "sample_dns_anomaly.pcap"
    wrpcap(str(out_path), pkts)
    print(f"Generated {out_path} ({len(pkts)} packets)")


def create_sample_malformed():
    """Generates corrupted file to verify resilient exception handling."""
    out_path = BASE_DIR / "sample_malformed.pcap"
    with open(out_path, "wb") as f:
        # Invalid magic and corrupted bytes
        f.write(b"CORRUPTED_NON_PCAP_DATA_FILE_PAYLOAD_1234567890")
    print(f"Generated {out_path} (corrupted capture)")


def create_url_samples():
    """Generates clean and suspicious demonstration URL lists."""
    clean_urls = [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://en.wikipedia.org/wiki/Computer_security",
        "https://stackoverflow.com/questions/tagged/python",
    ]
    with open(BASE_DIR / "sample_clean_urls.txt", "w", encoding="utf-8") as f:
        f.write("# Clean Benign Demonstration URLs\n")
        f.write("\n".join(clean_urls) + "\n")

    suspicious_urls = [
        "http://203.0.113.50/login/verify",
        "http://secure.account.verification.update-portal.bank.xyz/signin",
        "http://paypal.com.accounts-security-verify.top/auth/login.php",
        "http://192.168.1.10/banking/authenticate?token=secret123",
        "http://tinyurl.com/secure-login-account",
        "http://xn--microsft-e1a.xyz/update/password",
    ]
    with open(BASE_DIR / "sample_suspicious_urls.txt", "w", encoding="utf-8") as f:
        f.write("# Suspicious Phishing Demonstration URLs\n")
        f.write("\n".join(suspicious_urls) + "\n")


if __name__ == "__main__":
    create_sample_clean()
    create_sample_suspicious()
    create_sample_scan()
    create_sample_beacon()
    create_sample_dns_anomaly()
    create_sample_malformed()
    create_url_samples()
    print("All synthetic sample data generated successfully!")
