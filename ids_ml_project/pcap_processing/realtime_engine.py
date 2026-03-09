from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import time
from ml.realtime_ml import realtime_ml_update

WINDOW = 15
SYN_GLOBAL_THRESHOLD = 100
RATE_THRESHOLD = 20

def start_realtime_ids(interface=None):
    print("[*] Realtime IDS started")
    print(f"[*] Interface: {interface or 'default'}")
    print(f"[*] Window: {WINDOW}s")

    syn_times = deque()
    packet_times = defaultdict(deque)

    def on_packet(pkt):
        print("PKT:", pkt.summary())

        now = time.time()

        if IP not in pkt:
            return

        src = pkt[IP].src
        packet_times[src].append(now)

        # cleanup old packets
        while packet_times[src] and now - packet_times[src][0] > WINDOW:
            packet_times[src].popleft()

        # 🔥 BURST DETECTION
        if len(packet_times[src]) >= 10 and (packet_times[src][-1] - packet_times[src][0]) < 2:
            print(f"[ALERT] Burst traffic detected from {src}")
            packet_times[src].clear()

        # SYN detection
        if TCP in pkt and pkt[TCP].flags & 0x02:
            syn_times.append(now)

        while syn_times and now - syn_times[0] > WINDOW:
            syn_times.popleft()

        # 🔥 GLOBAL SYN FLOOD
        if len(syn_times) > SYN_GLOBAL_THRESHOLD:
            print(f"[ALERT] Global SYN flood ({len(syn_times)} SYNs/{WINDOW}s)")
            syn_times.clear()

        # 🔥 RATE-BASED DETECTION
        rate = len(packet_times[src]) / WINDOW
        if rate > RATE_THRESHOLD:
            print(f"[ALERT] High packet rate from {src} ({int(rate)} pkt/s)")
            packet_times[src].clear()
        # 🔥 REALTIME ML CHECK
        ml_score = realtime_ml_update(pkt)
        if ml_score is not None and ml_score > 0.6:
            print(f"[ALERT] ML anomaly detected (score={ml_score:.2f})")


    sniff(iface=interface, prn=on_packet, store=False)
