"""Offline PCAP packet extraction using Scapy.

Strict Security Control:
Never transmits or replays packets on the network. Purely passive local file parsing.
"""

import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw
from scapy.error import Scapy_Exception


def parse_pcap_capture(file_path: str) -> Dict[str, Any]:
    """
    Parses a PCAP/PCAPNG capture file offline and normalizes packet-level telemetry.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Capture file not found: {file_path}")

    # Compute SHA-256 hash
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    file_hash = sha256.hexdigest()

    try:
        packets = rdpcap(file_path)
    except Scapy_Exception as e:
        raise ValueError(f"Malformed or unsupported capture format: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to read capture file: {str(e)}")

    if len(packets) == 0:
        return {
            "filename": os.path.basename(file_path),
            "file_hash": file_hash,
            "packet_count": 0,
            "packets": [],
            "dns_queries": [],
            "http_events": [],
            "protocols": {},
            "duration_seconds": 0.0,
            "total_bytes": 0,
        }

    packet_records: List[Dict[str, Any]] = []
    dns_queries: List[Dict[str, Any]] = []
    http_events: List[Dict[str, Any]] = []
    protocols: Dict[str, int] = {}
    total_bytes = 0

    first_ts = None
    last_ts = None

    for pkt in packets:
        pkt_len = len(pkt)
        total_bytes += pkt_len

        # Scapy packet time is epoch float
        pkt_time_float = float(pkt.time)
        pkt_dt = datetime.fromtimestamp(pkt_time_float, tz=timezone.utc)

        if first_ts is None or pkt_time_float < first_ts:
            first_ts = pkt_time_float
        if last_ts is None or pkt_time_float > last_ts:
            last_ts = pkt_time_float

        src_ip = None
        dst_ip = None
        protocol = "OTHER"

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        src_port = 0
        dst_port = 0
        tcp_flag = ""

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            tcp_flag = str(pkt[TCP].flags)

            # Inspect HTTP request metadata if payload present
            if Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load)
                    if any(payload.startswith(m) for m in [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS "]):
                        lines = payload.split(b"\r\n")
                        first_line = lines[0].decode(errors="ignore")
                        method, uri, _ = (first_line.split(" ") + ["", ""])[:3]

                        host = ""
                        for line in lines[1:]:
                            if line.lower().startswith(b"host:"):
                                host = line.split(b":", 1)[1].strip().decode(errors="ignore")
                                break

                        http_events.append({
                            "timestamp": pkt_dt,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "method": method,
                            "uri": uri,
                            "host": host,
                        })
                except Exception:
                    pass

        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

            # Inspect DNS queries
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qd:
                    try:
                        qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                        qtype_num = dns.qd.qtype
                        qtype_str = "A" if qtype_num == 1 else ("AAAA" if qtype_num == 28 else str(qtype_num))

                        answers = []
                        if dns.an:
                            for i in range(dns.ancount):
                                try:
                                    an = dns.an[i]
                                    if hasattr(an, "rdata"):
                                        rdata = an.rdata
                                        answers.append(rdata.decode(errors="ignore") if isinstance(rdata, bytes) else str(rdata))
                                except Exception:
                                    pass

                        dns_queries.append({
                            "timestamp": pkt_dt,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "qname": qname,
                            "qtype": qtype_str,
                            "answers": answers,
                        })
                    except Exception:
                        pass

        elif ICMP in pkt:
            protocol = "ICMP"

        protocols[protocol] = protocols.get(protocol, 0) + 1

        if src_ip and dst_ip:
            packet_records.append({
                "timestamp": pkt_dt,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": pkt_len,
                "tcp_flag": tcp_flag,
            })

    duration = round(last_ts - first_ts, 3) if (first_ts and last_ts) else 0.0

    return {
        "filename": os.path.basename(file_path),
        "file_hash": file_hash,
        "packet_count": len(packets),
        "packets": packet_records,
        "dns_queries": dns_queries,
        "http_events": http_events,
        "protocols": protocols,
        "duration_seconds": duration,
        "total_bytes": total_bytes,
    }
