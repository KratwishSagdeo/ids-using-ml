from scapy.all import rdpcap, IP
import joblib
import pandas as pd
from typing import List, Dict
from feature_extractor import CICFlowFeatureExtractor
from db import IDSDatabase
import os


class PCAPAnalyzer:
    """
    Analyze PCAP files using CIC-IDS flow-based logic
    """

    def __init__(self, model_path: str, scaler_path: str, feature_names_path: str):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

        self.flow_extractor = CICFlowFeatureExtractor(feature_names_path)
        self.db = IDSDatabase()

    def analyze_pcap(self, pcap_path: str, save_to_db: bool = True) -> List[Dict]:
        print(f"📂 Loading PCAP: {pcap_path}")

        packets = rdpcap(pcap_path)
        print(f"📦 Packets loaded: {len(packets)}")

        alerts = []

        for pkt in packets:
            if IP not in pkt:
                continue

            completed_flows = self.flow_extractor.process_packet(pkt)

            for flow_df in completed_flows:
                # Scale features
                X = self.scaler.transform(flow_df)

                # Predict
                pred = self.model.predict(X)[0]
                proba = self.model.predict_proba(X)[0][1]

                if pred == 1:  # ATTACK
                    alert = {
                        "attack_type": "ATTACK",
                        "confidence": float(proba)
                    }

                    alerts.append(alert)

                    if save_to_db:
                        self.db.insert_alert_sync(
                            timestamp=None,
                            source_ip=None,
                            dest_ip=None,
                            source_port=None,
                            dest_port=None,
                            protocol=None,
                            attack_type="ATTACK",
                            confidence=float(proba),
                            packet_length=None,
                            flags=None,
                            payload_preview=None
                        )

                    print(f"🚨 ATTACK FLOW DETECTED | Confidence: {proba:.2%}")

        print("\n" + "=" * 60)
        print("PCAP ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"Malicious flows detected: {len(alerts)}")
        print("=" * 60)

        return alerts
