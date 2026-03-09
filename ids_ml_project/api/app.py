from fastapi import FastAPI, UploadFile, File, WebSocket
import joblib
import pandas as pd
import shutil
import asyncio

from pcap_processing.pcap_to_flow import pcap_to_features
from pcap_processing.rule_engine import analyze_pcap_rules
from ml.ml_detector import ml_detect

# -----------------------------
# App & global state
# -----------------------------
app = FastAPI()

clients = []          # websocket clients
alerts_buffer = []    # stored realtime alerts


# -----------------------------
# Load ML artifacts (UNCHANGED)
# -----------------------------
model = joblib.load("training/model.pkl")
scaler = joblib.load("training/scaler.pkl")


# =============================
# PCAP UPLOAD ENDPOINT
# (UNCHANGED BEHAVIOR)
# =============================
@app.post("/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    pcap_path = f"temp_{file.filename}"

    with open(pcap_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Rule-based detection
    alerts, total_packets = analyze_pcap_rules(pcap_path)

    # ML-based detection
    ml_alert, ml_score = ml_detect(pcap_path)
    if ml_alert:
        alerts.append(f"ML anomaly detected (score={ml_score:.2f})")

    return {
        "total_packets": total_packets,
        "alerts": alerts,
        "ml_score": round(ml_score, 3),
        "status": "malicious activity detected" if alerts else "no obvious attack detected"
    }


# =============================
# REALTIME ALERT INGEST
# (called from realtime IDS)
# =============================
@app.post("/ingest_alert")
async def ingest_alert(data: dict):
    alert = data.get("alert", "unknown alert")
    alerts_buffer.append(alert)

    # push to websocket clients
    for ws in clients:
        try:
            await ws.send_text(alert)
        except:
            pass

    return {"status": "ok"}


# =============================
# WEBSOCKET ENDPOINT
# =============================
@app.websocket("/ws/alerts")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)

    try:
        while True:
            await asyncio.sleep(1)
    except:
        clients.remove(ws)


# =============================
# BASIC HEALTH CHECK
# =============================
@app.get("/")
async def root():
    return {"status": "IDS API running"}
