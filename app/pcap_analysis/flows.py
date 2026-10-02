"""Network flow aggregation and session metrics engine."""

from typing import List, Dict, Any
from datetime import datetime


def aggregate_network_flows(packet_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups raw packet events into logical 5-tuple network flows:
    (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    flows_map: Dict[tuple, Dict[str, Any]] = {}

    for pkt in packet_events:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = pkt.get("src_port", 0)
        dst_port = pkt.get("dst_port", 0)
        protocol = pkt.get("protocol", "OTHER")
        pkt_len = pkt.get("length", 0)
        ts = pkt.get("timestamp")
        flag = pkt.get("tcp_flag", "")

        if not src_ip or not dst_ip:
            continue

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if flow_key not in flows_map:
            flows_map[flow_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": ts,
                "last_seen": ts,
                "duration": 0.0,
                "tcp_flags": set(),
            }

        f = flows_map[flow_key]
        f["packet_count"] += 1
        f["byte_count"] += pkt_len
        if flag:
            f["tcp_flags"].add(flag)

        if ts:
            if f["first_seen"] is None or ts < f["first_seen"]:
                f["first_seen"] = ts
            if f["last_seen"] is None or ts > f["last_seen"]:
                f["last_seen"] = ts

    flow_list: List[Dict[str, Any]] = []
    for flow in flows_map.values():
        if flow["first_seen"] and flow["last_seen"]:
            if isinstance(flow["first_seen"], datetime) and isinstance(flow["last_seen"], datetime):
                flow["duration"] = round((flow["last_seen"] - flow["first_seen"]).total_seconds(), 3)
            else:
                flow["duration"] = 0.0
        else:
            flow["duration"] = 0.0

        flow["tcp_flags"] = ",".join(sorted(list(flow["tcp_flags"]))) if flow["tcp_flags"] else ""
        flow_list.append(flow)

    flow_list.sort(key=lambda x: x["packet_count"], reverse=True)
    return flow_list
