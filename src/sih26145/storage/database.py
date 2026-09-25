"""Async SQLite storage engine for versioned threat alerts (sih26145.alert.v2)."""

import json
import os
import aiosqlite
from typing import List, Dict, Any, Optional
from sih26145.alerts.models import Alert, upgrade_v1_dict

SCHEMA_VERSION = 2  # PRAGMA user_version once all migrations have run
DB_PATH_ENV = "SIH26145_DB_PATH"


class AlertStorage:
    """Async SQLite storage engine for versioned threat alerts."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv(DB_PATH_ENV) or "alerts.db"
        self._conn: Optional[aiosqlite.Connection] = None
        self._initialized = False

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
        """Create or migrate the schema once per connection. File databases use WAL."""
        if self._initialized:
            return
        conn = await self.get_connection()
        if self.db_path != ":memory:":
            await conn.execute("PRAGMA journal_mode=WAL")
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
        async with conn.execute("PRAGMA user_version") as cur:
            (version,) = await cur.fetchone()
        if version < 2:
            await self._migrate_v1_to_v2(conn)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id)")
        await conn.commit()
        self._initialized = True

    async def _migrate_v1_to_v2(self, conn: aiosqlite.Connection):
        """Add the v2 columns and rewrite stored v1 JSON in place, in one transaction."""
        await conn.execute("BEGIN")
        try:
            await conn.execute("ALTER TABLE alerts ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0'")
            await conn.execute("ALTER TABLE alerts ADD COLUMN flow_id TEXT")
            await conn.execute("ALTER TABLE alerts ADD COLUMN observability_state TEXT")
            async with conn.execute("SELECT alert_id, json_data FROM alerts") as cur:
                rows = await cur.fetchall()
            for alert_id, raw in rows:
                try:
                    up = upgrade_v1_dict(json.loads(raw))
                except (ValueError, TypeError):
                    continue  # unreadable row: leave it, get_alerts already skips it
                await conn.execute(
                    "UPDATE alerts SET json_data = ?, schema_version = ?, flow_id = ? WHERE alert_id = ?",
                    (json.dumps(up), up["version"], up.get("flow_id"), alert_id),
                )
            await conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    async def save_alert(self, alert: Alert) -> str:
        """Save a structured Alert into SQLite database using parameterized query."""
        await self.init_db()
        conn = await self.get_connection()
        alert_dict = alert.to_dict()
        await conn.execute(
            """
            INSERT OR REPLACE INTO alerts
                (alert_id, timestamp, threat_class, severity, confidence, json_data,
                 schema_version, flow_id, observability_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert.timestamp,
                alert.threat_class,
                alert.severity,
                float(alert.confidence),
                json.dumps(alert_dict),
                alert.version,
                alert.flow_id,
                alert.observability_state,
            ),
        )
        await conn.commit()
        return alert.alert_id

    async def count_alerts(self) -> int:
        await self.init_db()
        conn = await self.get_connection()
        async with conn.execute("SELECT COUNT(*) FROM alerts") as cur:
            (n,) = await cur.fetchone()
        return int(n)

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
            self._initialized = False
