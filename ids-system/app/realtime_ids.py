from scapy.all import sniff, IP
import joblib
import sys
import signal
from datetime import datetime
import platform

from .feature_extractor import CICFlowFeatureExtractor
from .db import IDSDatabase


class RealtimeIDS:
    """
    Real-time flow-based IDS (future use only).
    NOT part of the current offline PCAP pipeline.
    """

    def __init__(self, model_path, scaler_path, feature_names_path, interface=None):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

        self.flow_extractor = CICFlowFeatureExtractor(feature_names_path)
        self.db = IDSDatabase()

        self.interface = interface
        self.packet_count = 0
        self.alert_count = 0

        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

    def shutdown(self, sig, frame):
        print("\n🛑 Stopping Real-Time IDS")
        print(f"Packets processed: {self.packet_count}")
        print(f"Alerts generated: {self.alert_count}")
        sys.exit(0)

    def detect_interface(self):
        try:
            if platform.system() == "Windows":
                from scapy.all import get_windows_if_list
                for iface in get_windows_if_list():
                    if iface.get("name"):
                        return iface["name"]
            else:
                from scapy.all import get_if_list
                for iface in get_if_list():
                    if not iface.startswith("lo"):
                        return iface
        except Exception:
            return None

    def packet_handler(self, packet):
        self.packet_count += 1

        if IP not in packet:
            return

        completed_flows = self.flow_extractor.process_packet(packet)

        for flow_df in completed_flows:
            X = self.scaler.transform(flow_df)
            pred = self.model.predict(X)[0]

            confidence = None
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                confidence = float(max(probs))

            if pred != 0:  # non-benign
                self.alert_count += 1

                self.db.insert_alert_sync(
                    event_time=datetime.utcnow().isoformat(),
                    attack_type=str(pred),
                    confidence=confidence
                )

                print(
                    f"🚨 ALERT | Class: {pred} | "
                    f"Confidence: {confidence if confidence else 'N/A'}"
                )

        if self.packet_count % 500 == 0:
            print(
                f"Packets: {self.packet_count} | Alerts: {self.alert_count}",
                end="\r"
            )

    def start(self):
        if not self.interface:
            self.interface = self.detect_interface()
            if not self.interface:
                print("❌ No network interface detected")
                return

        print("\n" + "=" * 60)
        print("🛡️ REAL-TIME IDS (FUTURE MODULE)")
        print("=" * 60)
        print(f"Interface: {self.interface}")
        print("Press Ctrl+C to stop")
        print("=" * 60 + "\n")

        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            store=False
        )
