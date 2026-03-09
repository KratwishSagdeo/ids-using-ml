from fastapi import FastAPI, UploadFile, File
import shutil
import uuid
import threading
import json
import os

from pcap_flow_detector import analyze_pcap
from db import init_db, get_conn

app = FastAPI()
init_db()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --------------------------------
# DB helper
# --------------------------------
def update_task(task_id, **kwargs):
    conn = get_conn()
    c = conn.cursor()

    for k, v in kwargs.items():
        c.execute(
            f"UPDATE tasks SET {k}=? WHERE task_id=?",
            (v, task_id)
        )

    conn.commit()
    conn.close()

# --------------------------------
# Background PCAP processor
# --------------------------------
def process_pcap(task_id: str, path: str):

    # progress callback passed to extractor
    def progress_cb(p):
        update_task(task_id, progress=p)

    try:
        alerts = analyze_pcap(path, progress_cb)

        update_task(
            task_id,
            status="completed",
            progress=100,
            alerts_detected=len(alerts),
            result=json.dumps(alerts)
        )

    except Exception as e:
        update_task(
            task_id,
            status="failed",
            result=json.dumps({"error": str(e)})
        )

# --------------------------------
# Upload endpoint
# --------------------------------
@app.post("/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    task_id = str(uuid.uuid4())
    path = os.path.join(UPLOAD_DIR, f"{task_id}_{file.filename}")

    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    conn = get_conn()
    conn.execute(
        """
        INSERT INTO tasks (task_id, status, progress, alerts_detected, result)
        VALUES (?, ?, ?, ?, ?)
        """,
        (task_id, "processing", 0, 0, None)
    )
    conn.commit()
    conn.close()

    threading.Thread(
        target=process_pcap,
        args=(task_id, path),
        daemon=True
    ).start()

    return {"task_id": task_id}

# --------------------------------
# Progress endpoint
# --------------------------------
@app.get("/progress/{task_id}")
def get_progress(task_id: str):
    conn = get_conn()
    c = conn.cursor()

    row = c.execute(
        "SELECT status, progress FROM tasks WHERE task_id=?",
        (task_id,)
    ).fetchone()

    conn.close()

    if not row:
        return {"error": "task not found"}

    return {
        "status": row[0],
        "progress": row[1]
    }

# --------------------------------
# Results endpoint
# --------------------------------
@app.get("/results/{task_id}")
def get_results(task_id: str):
    conn = get_conn()
    c = conn.cursor()

    row = c.execute(
        "SELECT status, alerts_detected, result FROM tasks WHERE task_id=?",
        (task_id,)
    ).fetchone()

    conn.close()

    if not row:
        return {"error": "task not found"}

    status, alert_count, result = row

    if status != "completed":
        return {
            "status": status,
            "message": "Analysis still in progress"
        }

    return {
        "status": "completed",
        "alerts_detected": alert_count,
        "alerts": json.loads(result) if result else []
    }
