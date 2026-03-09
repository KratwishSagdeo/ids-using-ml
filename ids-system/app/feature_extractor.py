from scapy.all import IP, TCP, UDP
import numpy as np
import pandas as pd
from collections import defaultdict
from typing import Dict, Tuple, List
import joblib


class Flow:
    """Represents a single CIC-IDS compatible flow"""

    def __init__(self, start_time: float, src_ip: str):
        self.start_time = start_time
        self.last_time = start_time
        self.src_ip = src_ip

        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []

        self.tcp_flags = defaultdict(int)

    def update(self, packet, direction: str, timestamp: float):
        length = len(packet)
        self.packet_lengths.append(length)
        self.last_time = timestamp

        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += length
            self.fwd_packet_lengths.append(length)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
            self.bwd_packet_lengths.append(length)

        if TCP in packet:
            flags = packet[TCP].flags
            self.tcp_flags["FIN"] += bool(flags & 0x01)
            self.tcp_flags["SYN"] += bool(flags & 0x02)
            self.tcp_flags["RST"] += bool(flags & 0x04)
            self.tcp_flags["PSH"] += bool(flags & 0x08)
            self.tcp_flags["ACK"] += bool(flags & 0x10)
            self.tcp_flags["URG"] += bool(flags & 0x20)

    def to_features(self) -> Dict:
        duration = max(self.last_time - self.start_time, 1e-6)

        def safe_stat(arr, fn):
            return fn(arr) if arr else 0.0

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": self.fwd_packets,
            "Total Backward Packets": self.bwd_packets,
            "Total Length of Fwd Packets": self.fwd_bytes,
            "Total Length of Bwd Packets": self.bwd_bytes,
            "Fwd Packet Length Max": safe_stat(self.fwd_packet_lengths, max),
            "Fwd Packet Length Min": safe_stat(self.fwd_packet_lengths, min),
            "Fwd Packet Length Mean": safe_stat(self.fwd_packet_lengths, np.mean),
            "Bwd Packet Length Max": safe_stat(self.bwd_packet_lengths, max),
            "Bwd Packet Length Min": safe_stat(self.bwd_packet_lengths, min),
            "Bwd Packet Length Mean": safe_stat(self.bwd_packet_lengths, np.mean),
            "Flow Bytes/s": (self.fwd_bytes + self.bwd_bytes) / duration,
            "Flow Packets/s": (self.fwd_packets + self.bwd_packets) / duration,
            "FIN Flag Count": self.tcp_flags["FIN"],
            "SYN Flag Count": self.tcp_flags["SYN"],
            "RST Flag Count": self.tcp_flags["RST"],
            "PSH Flag Count": self.tcp_flags["PSH"],
            "ACK Flag Count": self.tcp_flags["ACK"],
            "URG Flag Count": self.tcp_flags["URG"],
        }


class CICFlowFeatureExtractor:
    """Packet-by-packet feature extractor for future real-time IDS"""

    def __init__(self, feature_names_path: str, flow_timeout: float = 60.0):
        self.flows: Dict[Tuple, Flow] = {}
        self.feature_names = joblib.load(feature_names_path)
        self.flow_timeout = flow_timeout

    def _flow_key(self, pkt) -> Tuple:
        proto = pkt.proto
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt.sport if TCP in pkt or UDP in pkt else 0
        dport = pkt.dport if TCP in pkt or UDP in pkt else 0
        return (src, dst, sport, dport, proto)

    def process_packet(self, packet) -> List[pd.DataFrame]:
        if IP not in packet:
            return []

        ts = float(packet.time)
        key = self._flow_key(packet)
        rev_key = (key[1], key[0], key[3], key[2], key[4])

        if key in self.flows:
            flow = self.flows[key]
            direction = "fwd"
        elif rev_key in self.flows:
            flow = self.flows[rev_key]
            direction = "bwd"
        else:
            flow = Flow(ts, key[0])
            self.flows[key] = flow
            direction = "fwd"

        flow.update(packet, direction, ts)

        if ts - flow.start_time >= self.flow_timeout:
            features = flow.to_features()
            df = pd.DataFrame([features])
            df = df.reindex(columns=self.feature_names, fill_value=0)
            del self.flows[key]
            return [df]

        return []
