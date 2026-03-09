from scapy.all import rdpcap, TCP, IP
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict

# =========================
# Load ML artifacts
# =========================

model = joblib.load("ids_model.pkl")
scaler = joblib.load("scaler.pkl")
features = joblib.load("features.pkl")

# Detection threshold
threshold = 0.6

# =========================
# Flow configuration
# =========================

INACTIVITY_TIMEOUT = 60
MAX_FLOW_DURATION = 300

# =========================
# Helpers
# =========================

def init_flow(packet_time):
    return {
        "start_time": packet_time,
        "last_seen": packet_time,
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "pkt_lengths": [],
        "prev_time": None,
        "iat_sum": 0,
        "iat_count": 0,
        "syn": 0,
        "ack": 0,
        "rst": 0,
    }


def extract_features(flow):
    duration = flow["last_seen"] - flow["start_time"]
    pkt_lengths = flow["pkt_lengths"]

    mean_len = np.mean(pkt_lengths)
    std_len = np.std(pkt_lengths)

    mean_iat = (
        flow["iat_sum"] / flow["iat_count"]
        if flow["iat_count"] > 0 else 0
    )

    return np.array([[  
        duration,
        flow["fwd_packets"],
        flow["bwd_packets"],
        flow["fwd_bytes"],
        flow["bwd_bytes"],
        min(pkt_lengths),
        max(pkt_lengths),
        mean_len,
        std_len,
        mean_iat,
        flow["syn"],
        flow["ack"],
        flow["rst"],
    ]])


def infer_attack_pattern(flow):
    if flow["syn"] > 20 and flow["ack"] < 5:
        return "Port Scan"

    if flow["syn"] > 10 and flow["rst"] > 10:
        return "Brute Force"

    if flow["fwd_packets"] > 500 or flow["fwd_bytes"] > 1_000_000:
        return "Traffic Flood"

    if flow["iat_count"] > 0 and (flow["iat_sum"] / flow["iat_count"]) < 0.001:
        return "High-Rate Automation"

    return "Generic Malicious Activity"


# =========================
# MAIN ENTRY (FastAPI calls this)
# =========================

def analyze_pcap(pcap_path: str, progress_cb=None):

    flows = {}
    alerts = []
    dest_ip_sources = defaultdict(set)

    packets = rdpcap(pcap_path)
    total_packets = len(packets)
    processed_packets = 0

    # -------------------------------
    # STEP 1: Build flows
    # -------------------------------
    for pkt in packets:
        processed_packets += 1

        if progress_cb and processed_packets % 500 == 0:
            progress = min(98, int((processed_packets / total_packets) * 100))

            progress_cb(progress)

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        src_ip, dst_ip = ip.src, ip.dst
        src_port, dst_port = tcp.sport, tcp.dport
        proto = "TCP"

        pkt_time = pkt.time
        pkt_len = len(pkt)

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, proto)

        if fwd_key in flows:
            flow = flows[fwd_key]
            direction = "fwd"
        elif bwd_key in flows:
            flow = flows[bwd_key]
            direction = "bwd"
        else:
            flow = init_flow(pkt_time)
            flows[fwd_key] = flow
            direction = "fwd"

        flow["last_seen"] = pkt_time
        flow["pkt_lengths"].append(pkt_len)

        if direction == "fwd":
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt_len
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt_len

        if flow["prev_time"] is not None:
            flow["iat_sum"] += pkt_time - flow["prev_time"]
            flow["iat_count"] += 1

        flow["prev_time"] = pkt_time

        if tcp.flags & 0x02:
            flow["syn"] += 1
        if tcp.flags & 0x10:
            flow["ack"] += 1
        if tcp.flags & 0x04:
            flow["rst"] += 1
# Force progress to 99 after packet parsing
    if progress_cb:
        progress_cb(99)


    # -------------------------------
    # STEP 2: ML detection
    # -------------------------------
# -------------------------------
# STEP 2: ML detection
# -------------------------------
    MAX_FLOWS = 5000   # safety limit (TEMP)

    total_flows = len(flows)
    print("Flows count:", total_flows)

    for i, (key, flow) in enumerate(flows.items()):
        if i >= MAX_FLOWS:
            break

    X = extract_features(flow)
    X_df = pd.DataFrame(X, columns=features)
    X_scaled = scaler.transform(X_df)

    proba = model.predict_proba(X_scaled)[0][1]

    if proba >= threshold:
        src, dst = key[0], key[1]
        dest_ip_sources[dst].add(src)

        alerts.append({
    "src_ip": src,
    "dst_ip": dst,
    "src_port": key[2],
    "dst_port": key[3],
    "malicious": True,
    "confidence": round(float(proba), 3)
})


    # heartbeat so it doesn't look stuck
    if progress_cb and i % 500 == 0:
        progress_cb(99)


    # -------------------------------
    # STEP 3: DoS vs DDoS
    # -------------------------------
    for alert in alerts:
        dst = alert["dst_ip"]
        alert["attack_type"] = "DDoS" if len(dest_ip_sources[dst]) > 3 else "DoS"
    if progress_cb:
        progress_cb(100)

    return alerts
