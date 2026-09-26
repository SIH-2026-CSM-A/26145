"""Async SQLite storage engine for versioned threat alerts (sih26145.alert.v2)."""

import json
import os
import aiosqlite
from typing import List, Dict, Any, Optional
from sih26145.alerts.models import Alert, upgrade_v1_dict
from sih26145.storage.chain import GENESIS, ROW_SQL, record_hash, verify_rows

_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SCHEMA_VERSION = 3  # PRAGMA user_version once all migrations have run
DB_PATH_ENV = "SIH26145_DB_PATH"


class AlertStorage:
    """Async SQLite storage engine for versioned threat alerts."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv(DB_PATH_ENV) or "alerts.db"
        self._conn: Optional[aiosqlite.Connection] = None
        self._initialized = False
        self._head = GENESIS  # record_hash of the last stored alert (storage/chain.py)
        self._seq = 0

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
        if version < 3:
            await self._migrate_v2_to_v3(conn)
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_class ON alerts(threat_class)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_campaign ON alerts(campaign_id)")
        await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_seq ON alerts(seq)")
        await conn.commit()
        async with conn.execute("SELECT seq, record_hash FROM alerts ORDER BY seq DESC LIMIT 1") as cur:
            last = await cur.fetchone()
        self._seq, self._head = (last[0] + 1, last[1]) if last else (0, GENESIS)
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

    async def _migrate_v2_to_v3(self, conn: aiosqlite.Connection):
        """Hash chain columns. Rows already stored are chained now, in insertion order: the chain
        attests to them from this migration on, not from when they were written."""
        await conn.execute("BEGIN")
        try:
            for col in ("seq INTEGER", "prev_hash TEXT", "record_hash TEXT", "campaign_id TEXT"):
                await conn.execute(f"ALTER TABLE alerts ADD COLUMN {col}")
            async with conn.execute("SELECT rowid, json_data FROM alerts ORDER BY rowid") as cur:
                rows = await cur.fetchall()
            prev = GENESIS
            for seq, (rowid, raw) in enumerate(rows):
                try:
                    d = json.loads(raw)
                except (ValueError, TypeError):
                    d = {"unreadable_json_data": raw}  # chained as found, never dropped
                d["record_hash"] = h = record_hash(prev, d)
                # v2 stored the unrounded confidence in its column; the hashed JSON's value wins
                await conn.execute(
                    "UPDATE alerts SET seq = ?, prev_hash = ?, record_hash = ?, campaign_id = ?, json_data = ?, "
                    "confidence = COALESCE(?, confidence) WHERE rowid = ?",
                    (seq, prev, h, d.get("campaign_id"), json.dumps(d), d.get("confidence"), rowid))
                prev = h
            await conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    async def save_alert(self, alert: Alert) -> str:
        """Append an alert to the hash chain (storage/chain.py). Plain INSERT: a chained row is
        never replaced; a duplicate alert_id is an error."""
        await self.init_db()
        conn = await self.get_connection()
        alert.record_hash = None
        alert.record_hash = record_hash(self._head, alert.to_dict())
        alert_dict = alert.to_dict()
        try:
            await self._insert(conn, alert, alert_dict)
        except Exception:
            await conn.rollback()
            raise
        self._seq, self._head = self._seq + 1, alert.record_hash
        return alert.alert_id

    async def _insert(self, conn, alert: Alert, alert_dict: dict) -> None:
        await conn.execute(
            """
            INSERT INTO alerts
                (alert_id, timestamp, threat_class, severity, confidence, json_data,
                 schema_version, flow_id, observability_state, seq, prev_hash, record_hash, campaign_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                alert_dict["timestamp"],
                alert.threat_class,
                alert.severity,
                alert_dict["confidence"],
                json.dumps(alert_dict),
                alert.version,
                alert.flow_id,
                alert.observability_state,
                self._seq,
                self._head,
                alert.record_hash,
                alert.campaign_id,
            ),
        )
        await conn.commit()

    async def _rows(self, sql: str, params=()) -> List[Dict[str, Any]]:
        await self.init_db()
        conn = await self.get_connection()
        out = []
        async with conn.execute(sql, params) as cur:
            async for (raw,) in cur:
                try:
                    out.append(json.loads(raw))
                except (ValueError, TypeError):
                    continue
        return out

    async def get_campaigns(self, limit: int = 5000) -> List[Dict[str, Any]]:
        """Campaign summaries from the most recent `limit` correlated alerts, newest first."""
        rows = await self._rows("SELECT json_data FROM alerts WHERE campaign_id IS NOT NULL ORDER BY seq DESC LIMIT ?",
                                (max(1, min(50_000, int(limit))),))
        camps: Dict[str, Dict[str, Any]] = {}
        for a in reversed(rows):
            corr = (a.get("detection") or {}).get("correlation") or {}
            c = camps.setdefault(a["campaign_id"], {
                "campaign_id": a["campaign_id"], "alerts": 0, "hosts": [], "threat_classes": [], "tactics": [],
                "first_seen": a["timestamp"], "last_seen": a["timestamp"], "max_severity": a["severity"],
                "not_merged": []})
            c["alerts"] += 1
            c["first_seen"], c["last_seen"] = min(c["first_seen"], a["timestamp"]), max(c["last_seen"], a["timestamp"])
            for key, val in (("hosts", corr.get("host")), ("threat_classes", a["threat_class"]),
                             ("tactics", corr.get("tactic"))):
                if val and val not in c[key]:
                    c[key].append(val)
            if _RANK.get(a["severity"], 0) > _RANK.get(c["max_severity"], 0):
                c["max_severity"] = a["severity"]
            for note in corr.get("not_merged") or []:
                if note not in c["not_merged"]:
                    c["not_merged"].append(note)
        return sorted(camps.values(), key=lambda c: c["last_seen"], reverse=True)

    async def get_campaign_alerts(self, campaign_id: str) -> List[Dict[str, Any]]:
        return await self._rows("SELECT json_data FROM alerts WHERE campaign_id = ? ORDER BY seq LIMIT 5000",
                                (str(campaign_id),))

    async def host_timeline(self, ip: str) -> List[Dict[str, Any]]:
        """Observed stages of one internal host, in order of first sighting: one entry per
        (tactic, threat class) with first/last seen and the alert count. No prediction."""
        rows = await self._rows(
            "SELECT json_data FROM alerts WHERE json_extract(json_data, '$.detection.correlation.host') = ? "
            "ORDER BY seq LIMIT 10000", (str(ip),))
        stages: Dict[tuple, Dict[str, Any]] = {}
        for a in rows:
            corr = a["detection"]["correlation"]
            key = (a.get("host_stage"), a["threat_class"])
            st = stages.setdefault(key, {"tactic_id": a.get("host_stage"), "tactic": corr.get("tactic"),
                                         "threat_class": a["threat_class"], "first_seen": a["timestamp"],
                                         "last_seen": a["timestamp"], "alerts": 0, "campaign_ids": []})
            st["alerts"] += 1
            st["first_seen"], st["last_seen"] = min(st["first_seen"], a["timestamp"]), max(st["last_seen"], a["timestamp"])
            if a.get("campaign_id") and a["campaign_id"] not in st["campaign_ids"]:
                st["campaign_ids"].append(a["campaign_id"])
        return sorted(stages.values(), key=lambda s: s["first_seen"])

    async def verify_chain(self) -> dict:
        """Recompute the whole chain (storage/chain.verify_rows) on this connection."""
        await self.init_db()
        conn = await self.get_connection()
        async with conn.execute(ROW_SQL) as cur:
            return verify_rows(await cur.fetchall())

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
            self._head, self._seq = GENESIS, 0
