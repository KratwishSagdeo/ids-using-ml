import time
import numpy as np
import joblib
from collections import defaultdict, deque

# load trained model
model = joblib.load("training/model.pkl")
scaler = joblib.load("training/scaler.pkl")

WINDOW = 15

# buffers
packet_count = defaultdict(int)
byte_count = defaultdict(int)
timestamps = defaultdict(deque)

def realtime_ml_update(pkt):
    now = time.time()
    src = pkt[0][1].src if hasattr(pkt[0][1], "src") else None
    if not src:
        return None

    packet_count[src] += 1
    byte_count[src] += len(pkt)
    timestamps[src].append(now)

    # cleanup old data
    while timestamps[src] and now - timestamps[src][0] > WINDOW:
        timestamps[src].popleft()

    if len(timestamps[src]) < 20:
        return None

    duration = timestamps[src][-1] - timestamps[src][0]
    duration = max(duration, 0.0001)

    features = np.array([[
        duration,
        packet_count[src],
        0,                       # backward packets (unknown realtime)
        byte_count[src],
        0,
        byte_count[src],
        0,
        packet_count[src] / duration,
        byte_count[src] / duration
    ]])

    X = scaler.transform(features)
    score = model.predict_proba(X)[0][1]

    # reset after evaluation
    packet_count[src] = 0
    byte_count[src] = 0
    timestamps[src].clear()

    return score
