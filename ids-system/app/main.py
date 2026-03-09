from fastapi import FastAPI, UploadFile, File, HTTPException
from datetime import datetime
import os
import shutil

from app.pcap_feature_bridge import PCAPFeatureBridge
from app.db import IDSDatabase


app = FastAPI(
    title="Intrusion Detection System API",
    description="Flow-based IDS using CIC-IDS 2017 and XGBoost (Hybrid IDS)",
    version="1.0.0"
)

# Paths
MODEL_PATH = os.path.join("models", "ids_model.pkl")
SCALER_PATH = os.path.join("models", "scaler.pkl")
FEATURE_NAMES_PATH = os.path.join("models", "feature_names.pkl")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

db = IDSDatabase()
pcap_bridge = None


@app.on_event("startup")
async def startup_event():
    global pcap_bridge

    missing = []
    for path in [MODEL_PATH, SCALER_PATH, FEATURE_NAMES_PATH]:
        if not os.path.exists(path):
            missing.append(path)

    if missing:
        print("❌ Missing required model artifacts:")
        for m in missing:
            print("   ", m)
        print("API will start in degraded mode.")
        return

    try:
        pcap_bridge = PCAPFeatureBridge(
            model_path=MODEL_PATH,
            scaler_path=SCALER_PATH,
            feature_names_path=FEATURE_NAMES_PATH
        )
        print("✅ IDS model, scaler, and feature schema loaded")
    except Exception as e:
        print(f"❌ Failed to initialize PCAPFeatureBridge: {e}")


@app.get("/")
async def root():
    return {
        "service": "Flow-based Intrusion Detection System",
        "dataset": "CIC-IDS 2017",
        "model": "XGBoost",
        "mode": "Offline PCAP analysis (Hybrid IDS)"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy" if pcap_bridge else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "model_loaded": pcap_bridge is not None
    }


@app.post("/analyze-pcap")
async def analyze_pcap(
    file: UploadFile = File(...),
    save_to_db: bool = True
):
    if not pcap_bridge:
        raise HTTPException(status_code=503, detail="Model not loaded")

    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap or .pcapng files are supported"
        )

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    try:
        # Save uploaded file
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # Process PCAP (HYBRID IDS happens inside the bridge)
        results = pcap_bridge.process_path(file_path)

        alerts = []

        for result in results:
            for alert in result["alerts"]:
                alerts.append(alert)

                if save_to_db:
                    db.insert_alert_sync(
                        event_time=result["timestamp"],
                        attack_type=alert["attack_type"],
                        confidence=alert.get("confidence")
                    )

        return {
            "status": "success",
            "filename": file.filename,
            "timestamp": datetime.utcnow().isoformat(),
            "total_flows": sum(r["total_flows"] for r in results),
            "malicious_flows": len(alerts),
            "alerts": alerts[:50]
        }

    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


@app.get("/alerts")
async def get_alerts(limit: int = 100):
    alerts = await db.get_recent_alerts(limit)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/statistics")
async def statistics():
    stats = await db.get_statistics()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "statistics": stats
    }


@app.get("/model/info")
async def model_info():
    if not pcap_bridge:
        raise HTTPException(status_code=503, detail="Model not loaded")

    return {
        "model_type": type(pcap_bridge.model).__name__,
        "dataset": "CIC-IDS 2017",
        "num_features": len(pcap_bridge.feature_names),
        "detection_mode": "Hybrid (Rule-based + ML)"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
