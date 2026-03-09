from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

def pcap_to_features(pcap_file):
    packets = rdpcap(pcap_file)

    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        proto = None
        sport = dport = 0

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue

        key = (
            pkt[IP].src,
            pkt[IP].dst,
            sport,
            dport,
            proto
        )

        if key not in flows:
            flows[key] = {
                "start": pkt.time,
                "end": pkt.time,
                "fwd_pkts": 0,
                "bwd_pkts": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
                "fwd_pkt_sizes": [],
                "bwd_pkt_sizes": []
            }

        flow = flows[key]
        flow["end"] = pkt.time

        if pkt[IP].src == key[0]:
            flow["fwd_pkts"] += 1
            flow["fwd_bytes"] += len(pkt)
            flow["fwd_pkt_sizes"].append(len(pkt))
        else:
            flow["bwd_pkts"] += 1
            flow["bwd_bytes"] += len(pkt)
            flow["bwd_pkt_sizes"].append(len(pkt))

    rows = []

    for flow in flows.values():
        duration = max(flow["end"] - flow["start"], 0.000001)

        total_packets = flow["fwd_pkts"] + flow["bwd_pkts"]
        total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

        rows.append([
            duration,
            flow["fwd_pkts"],
            flow["bwd_pkts"],
            flow["fwd_bytes"],
            flow["bwd_bytes"],
            max(flow["fwd_pkt_sizes"]) if flow["fwd_pkt_sizes"] else 0,
            max(flow["bwd_pkt_sizes"]) if flow["bwd_pkt_sizes"] else 0,
            total_packets / duration,
            total_bytes / duration
        ])

    df = pd.DataFrame(rows, columns=[
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Bwd Packet Length Max",
        "Flow Packets/s",
        "Flow Bytes/s"
    ])

    return df
