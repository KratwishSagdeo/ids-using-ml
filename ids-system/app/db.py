import sqlite3
import aiosqlite
from datetime import datetime
from typing import Optional, List, Dict
import os

class IDSDatabase:
    def __init__(self, db_path: str = "ids_alerts.db"):
        self.db_path = db_path
        self._ensure_db_dir()
        self._init_db()

    def _ensure_db_dir(self):
        """Ensure directory for DB exists"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def _init_db(self):
        """Initialize database schema (sync, one-time)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode=WAL;")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                attack_type TEXT NOT NULL,
                confidence REAL,
                packet_length INTEGER,
                flags TEXT,
                payload_preview TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_time ON alerts(event_time)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_attack_type ON alerts(attack_type)"
        )

        conn.commit()
        conn.close()

    async def insert_alert(
        self,
        event_time: Optional[str] = None,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        dest_port: Optional[int] = None,
        protocol: Optional[str] = None,
        attack_type: str = "Unknown",
        confidence: Optional[float] = None,
        packet_length: Optional[int] = None,
        flags: Optional[str] = None,
        payload_preview: Optional[str] = None
    ) -> int:
        """Insert a new IDS alert asynchronously"""
        if event_time is None:
            event_time = datetime.utcnow().isoformat()

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                INSERT INTO alerts (
                    event_time, source_ip, dest_ip, source_port, dest_port,
                    protocol, attack_type, confidence, packet_length,
                    flags, payload_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_time, source_ip, dest_ip, source_port, dest_port,
                protocol, attack_type, confidence, packet_length,
                flags, payload_preview
            ))
            await db.commit()
            return cursor.lastrowid

    async def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """Fetch most recent alerts"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM alerts
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_alerts_by_type(self, attack_type: str) -> List[Dict]:
        """Fetch alerts filtered by attack type"""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT * FROM alerts
                WHERE attack_type = ?
                ORDER BY created_at DESC
            """, (attack_type,))
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_statistics(self) -> Dict:
        """Return alert statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = (await cursor.fetchone())[0]

            cursor = await db.execute("""
                SELECT attack_type, COUNT(*) 
                FROM alerts
                GROUP BY attack_type
                ORDER BY COUNT(*) DESC
            """)
            alerts_by_type = {
                row[0]: row[1] for row in await cursor.fetchall()
            }

            cursor = await db.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE datetime(created_at) > datetime('now', '-1 day')
            """)
            last_24h = (await cursor.fetchone())[0]

            return {
                "total_alerts": total_alerts,
                "alerts_by_type": alerts_by_type,
                "last_24h": last_24h
            }

    async def clear_old_alerts(self, days: int = 30):
        """Delete alerts older than N days"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                DELETE FROM alerts
                WHERE datetime(created_at) < datetime('now', ?)
            """, (f'-{days} days',))
            await db.commit()

    def insert_alert_sync(
        self,
        **kwargs
    ) -> int:
        """Sync insert (fallback for non-async contexts)"""
        if "event_time" not in kwargs or kwargs["event_time"] is None:
            kwargs["event_time"] = datetime.utcnow().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO alerts (
                event_time, source_ip, dest_ip, source_port, dest_port,
                protocol, attack_type, confidence, packet_length,
                flags, payload_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            kwargs.get("event_time"),
            kwargs.get("source_ip"),
            kwargs.get("dest_ip"),
            kwargs.get("source_port"),
            kwargs.get("dest_port"),
            kwargs.get("protocol"),
            kwargs.get("attack_type", "Unknown"),
            kwargs.get("confidence"),
            kwargs.get("packet_length"),
            kwargs.get("flags"),
            kwargs.get("payload_preview")
        ))

        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        return alert_id
