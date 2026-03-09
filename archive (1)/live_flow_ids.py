from scapy.all import sniff, TCP, IP
import time
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

# =========================
# Runtime configuration
# =========================

THRESHOLD = 0.6          # ML confidence threshold
WINDOW_SECONDS = 10      # Run ML every N seconds
FLOW_TIMEOUT = 30        # Remove inactive flows

# =========================
# Global state (runtime only)
# =========================

flows = {}
last_inference_time = time.time()

# =========================
# Flow helpers
# =========================

def init_flow(ts):
    return {
        "start_time": ts,
        "last_seen": ts,
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
    pkts = flow["pkt_lengths"]
    if not pkts:
        return None

    mean_iat = (
        flow["iat_sum"] / flow["iat_count"]
        if flow["iat_count"] > 0 else 0
    )

    return np.array([[
        flow["last_seen"] - flow["start_time"],
        flow["fwd_packets"],
        flow["bwd_packets"],
        flow["fwd_bytes"],
        flow["bwd_bytes"],
        min(pkts),
        max(pkts),
        np.mean(pkts),
        np.std(pkts),
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
# ML inference on active flows
# =========================

def run_inference(now):
    attackers = defaultdict(set)
    expired = []

    for key, flow in flows.items():
        if now - flow["last_seen"] > FLOW_TIMEOUT:
            expired.append(key)
            continue

        X = extract_features(flow)
        if X is None:
            continue

        X_df = pd.DataFrame(X, columns=features)
        X_scaled = scaler.transform(X_df)

        proba = model.predict_proba(X_scaled)[0][1]

        if proba >= THRESHOLD:
            src, dst = key[0], key[1]
            attackers[dst].add(src)

            attack_type = (
                "DDoS" if len(attackers[dst]) > 3 else "DoS"
            )

            attack_pattern = infer_attack_pattern(flow)

            print(
                f"[ALERT] {attack_type} | {attack_pattern} | "
                f"{src} → {dst} | confidence={proba:.2f}"
            )

    for k in expired:
        del flows[k]

# =========================
# Packet handler (real-time)
# =========================

def handle_packet(pkt):
    global last_inference_time

    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    now = time.time()
    ip = pkt[IP]
    tcp = pkt[TCP]

    src, dst = ip.src, ip.dst
    sport, dport = tcp.sport, tcp.dport

    fwd_key = (src, dst, sport, dport, "TCP")
    bwd_key = (dst, src, dport, sport, "TCP")

    if fwd_key in flows:
        flow = flows[fwd_key]
        direction = "fwd"
    elif bwd_key in flows:
        flow = flows[bwd_key]
        direction = "bwd"
    else:
        flow = init_flow(now)
        flows[fwd_key] = flow
        direction = "fwd"

    flow["last_seen"] = now
    flow["pkt_lengths"].append(len(pkt))

    if direction == "fwd":
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += len(pkt)
    else:
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += len(pkt)

    if flow["prev_time"] is not None:
        flow["iat_sum"] += now - flow["prev_time"]
        flow["iat_count"] += 1

    flow["prev_time"] = now

    if tcp.flags & 0x02:
        flow["syn"] += 1
    if tcp.flags & 0x10:
        flow["ack"] += 1
    if tcp.flags & 0x04:
        flow["rst"] += 1

    if now - last_inference_time >= WINDOW_SECONDS:
        run_inference(now)
        last_inference_time = now

# =========================
# Start live IDS
# =========================

if __name__ == "__main__":
    print("🚨 Real-time Flow-based ML IDS running")
    print("⚠️  Run as Administrator (Windows)")
    print("🛑 Press CTRL+C to stop\n")

    sniff(prn=handle_packet, store=False)
