from scapy.all import rdpcap, IP, TCP
from collections import defaultdict

def analyze_pcap_rules(pcap_file):
    packets = rdpcap(pcap_file)

    alerts = []

    syn_count = defaultdict(int)
    port_scan_tracker = defaultdict(set)
    packet_rate = defaultdict(list)

    total_syn = 0

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        now = pkt.time
        packet_rate[src].append(now)

        if TCP in pkt:
            flags = pkt[TCP].flags

            # ✅ SYN detection (CORRECT)
            if flags & 0x02:
                syn_count[src] += 1
                total_syn += 1

            # Port scan detection
            port_scan_tracker[src].add(pkt[TCP].dport)

    # Per-IP SYN flood
    for src, count in syn_count.items():
        if count > 200:
            alerts.append(f"SYN flood detected from {src} ({count} SYN packets)")

    # Global SYN flood (spoof-safe)
    if total_syn > 500:
        alerts.append(f"Global SYN flood detected ({total_syn} SYN packets)")

    # Port scan
    for src, ports in port_scan_tracker.items():
        if len(ports) > 50:
            alerts.append(f"Port scan detected from {src} ({len(ports)} ports scanned)")

    # Packet rate
    for src, times in packet_rate.items():
        if len(times) < 20:
            continue
        duration = max(times) - min(times)
        if duration <= 0:
            continue
        rate = len(times) / duration
        if rate > 200:
            alerts.append(f"High packet rate detected from {src} ({int(rate)} pkt/s)")

    return alerts, len(packets)
