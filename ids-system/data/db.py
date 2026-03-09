import sqlite3
from typing import Optional

DB_NAME = "ids_tasks.db"

def get_conn():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        status TEXT,
        progress INTEGER,
        alerts_detected INTEGER,
        result TEXT
    )
    """)

    conn.commit()
    conn.close()
