import joblib
import numpy as np
from pcap_processing.pcap_to_flow import pcap_to_features

# Load trained artifacts
model = joblib.load("training/model.pkl")
scaler = joblib.load("training/scaler.pkl")

def ml_detect(pcap_file, threshold=0.5):
    """
    Returns:
    - alert (bool)
    - anomaly_score (float)
    """

    df = pcap_to_features(pcap_file)

    if df.empty:
        return False, 0.0

    X = scaler.transform(df)
    probs = model.predict_proba(X)[:, 1]

    mean_score = float(np.mean(probs))

    if mean_score >= threshold:
        return True, mean_score

    return False, mean_score
