"""Async SQLite storage engine for versioned threat alerts (sih26145.alert.v1)."""

import json
import os
import aiosqlite
from typing import List, Dict, Any, Optional
from sih26145.alerts.models import Alert


class AlertStorage:
    """Async SQLite storage engine for versioned threat alerts."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            self.db_path = os.path.expanduser("~/NewProjects/sih26145/alerts.db")
        else:
            self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def get_connection(self) -> aiosqlite.Connection:
        """Get or create persistent database connection."""
        if self._conn is None:
            if self.db_path != ":memory:":
                db_dir = os.path.dirname(os.path.abspath(self.db_path))
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
            self._conn = await aiosqlite.connect(self.db_path)
        return self._conn

    async def init_db(self):
        """Initialize SQLite database, create alerts table and indexes if not exist."""
        conn = await self.get_connection()
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                threat_class TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                json_data TEXT NOT NULL
            )
        """)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        await conn.commit()

    async def save_alert(self, alert: Alert) -> str:
        """Save a structured Alert into SQLite database using parameterized query."""
        conn = await self.get_connection()
        await self.init_db()
        alert_dict = alert.to_dict()
        await conn.execute(
            """
            INSERT OR REPLACE INTO alerts (alert_id, timestamp, threat_class, severity, confidence, json_data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.timestamp,
                alert.threat_class,
                alert.severity,
                float(alert.confidence),
                json.dumps(alert_dict),
            ),
        )
        await conn.commit()
        return alert.alert_id

    async def get_alerts(
        self,
        threat_class: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieve persisted alerts with parameterized filtering and ordering."""
        conn = await self.get_connection()
        await self.init_db()
        
        # Enforce valid positive limit bound
        safe_limit = max(1, min(1000, int(limit)))
        
        query = "SELECT json_data FROM alerts"
        conditions = []
        params: List[Any] = []

        if threat_class:
            conditions.append("threat_class = ?")
            params.append(str(threat_class))
        if severity:
            conditions.append("severity = ?")
            params.append(str(severity))

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(safe_limit)

        results = []
        async with conn.execute(query, params) as cursor:
            async for row in cursor:
                try:
                    results.append(json.loads(row[0]))
                except (ValueError, TypeError):
                    continue
        return results

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single alert by alert_id using parameterized query."""
        conn = await self.get_connection()
        await self.init_db()
        async with conn.execute("SELECT json_data FROM alerts WHERE alert_id = ?", (str(alert_id),)) as cursor:
            row = await cursor.fetchone()
            if row:
                try:
                    return json.loads(row[0])
                except (ValueError, TypeError):
                    return None
        return None

    async def close(self):
        """Close persistent database connection."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
