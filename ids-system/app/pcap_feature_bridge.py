import os
from pyexpat import features
import joblib
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime

FLOW_TIMEOUT = 60  # seconds


class PCAPFeatureBridge:
    def __init__(
        self,
        model_path="ids_model.pkl",
        scaler_path="scaler.pkl",
        feature_names_path="feature_names.pkl"
    ):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_names = joblib.load(feature_names_path)

    def _flow_key(self, pkt):
        if IP not in pkt:
            return None

        proto = None
        sport, dport = 0, 0

        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            return None

        return (
            pkt[IP].src,
            pkt[IP].dst,
            sport,
            dport,
            proto
        )

    def _extract_flow_features(self, packets):
        times = [pkt.time for pkt in packets]
        sizes = [len(pkt) for pkt in packets]

        duration = max(times) - min(times) if len(times) > 1 else 0.0
        total_packets = len(packets)
        total_bytes = sum(sizes)

        fwd_packets = sum(1 for p in packets if IP in p and p[IP].src == packets[0][IP].src)
        bwd_packets = total_packets - fwd_packets

        syn_count = sum(
            1 for p in packets if TCP in p and p[TCP].flags & 0x02
        )

        features = {
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": total_bytes,
            "Flow Bytes/s": total_bytes / duration if duration > 0 else 0.0,
            "Flow Packets/s": total_packets / duration if duration > 0 else 0.0,
            "SYN Flag Count": syn_count
        }

        return features

    def pcap_to_dataframe(self, pcap_path):
        packets = rdpcap(pcap_path)
        flows = defaultdict(list)

        for pkt in packets:
            key = self._flow_key(pkt)
            if key:
                flows[key].append(pkt)

        rows = []

        for _, pkts in flows.items():
            row = self._extract_flow_features(pkts)
            rows.append(row)

        if not rows:
            rows.append({})

        df = pd.DataFrame(rows)

        # Ensure ALL expected features exist
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0.0

        # Exact feature order
        df = df[self.feature_names]

        return df

    def predict_pcap(self, pcap_path):
        df = self.pcap_to_dataframe(pcap_path)
        scaled = self.scaler.transform(df)
        alerts = []

        for i, row in df.iterrows():
            feature_dict = row.to_dict()

        # 🔥 RULE-BASED CHECK FIRST
            rule_alert = self.rule_based_detection(feature_dict)
            if rule_alert:
                alerts.append(rule_alert)
                continue  # do NOT send to ML

        # 🤖 ML-BASED DETECTION
        X = self.scaler.transform([row.values])
        pred = self.model.predict(X)[0]

        confidence = None
        if hasattr(self.model, "predict_proba"):
            confidence = float(max(self.model.predict_proba(X)[0]))

        if pred != 0:
            alerts.append({
            "attack_type": str(pred),
            "confidence": confidence,
            "source": "ml"
        })

        return {
            "pcap": os.path.basename(pcap_path),
            "timestamp": datetime.utcnow().isoformat(),
            "total_flows": len(df),
            "alerts": alerts
        }

    def process_path(self, path):
        results = []

        if os.path.isdir(path):
            for file in os.listdir(path):
                if file.endswith(".pcap"):
                    results.append(
                        self.predict_pcap(os.path.join(path, file))
                    )
        else:
            results.append(self.predict_pcap(path))

        return results
    def rule_based_detection(self, features: dict):
        """
    Simple heuristic rules for attacks NOT covered by the ML model
        """

    # SYN Flood heuristic
        if (
        features.get("SYN Flag Count", 0) > 100 and
        features.get("Total Backward Packets", 0) == 0 and
        features.get("Flow Packets/s", 0) > 50
    ):
            return {
            "attack_type": "SYN_FLOOD",
            "confidence": 1.0,
            "source": "rule"
        }

        return None

