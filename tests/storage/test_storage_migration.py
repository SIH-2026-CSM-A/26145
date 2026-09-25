"""AlertStorage v2: migrating a v1 database in place, WAL, and the v2 columns."""

import json
import sqlite3

import pytest

from sih26145.alerts.models import Alert
from sih26145.storage.database import AlertStorage

V1_ALERT = {
    "$schema": "https://sih26145.ntro.gov.in/schemas/alert.v1.json",
    "version": "1.0",
    "alert_id": "urn:uuid:11111111-1111-1111-1111-111111111111",
    "timestamp": "2026-09-16T15:00:00+00:00",
    "threat_class": "THREAT_DNS_TUNNEL",
    "detector": {"name": "dns_tunnel_detector", "type": "RULE", "version": "1.0.0"},
    "flow": {"src_ip": "192.168.1.52", "src_port": 54585, "dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP"},
    "confidence": 0.92,
    "severity": "HIGH",
    "evidence": {"rule_matches": ["RULE_DNS_TUNNEL_PAYLOAD_DEPTH"], "ml_scores": [],
                 "metrics": {"dns_max_subdomain_depth": 5, "legacy_only": 1}},
    "feature_summary": {"total_packets": 5, "total_bytes": 500, "pps": 1.0, "bps": 100.0},
}


def make_v1_db(path):
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL,
                   threat_class TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL,
                   json_data TEXT NOT NULL)""")
    con.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?)", (
        V1_ALERT["alert_id"], V1_ALERT["timestamp"], V1_ALERT["threat_class"],
        V1_ALERT["severity"], V1_ALERT["confidence"], json.dumps(V1_ALERT)))
    con.commit()
    con.close()


@pytest.mark.asyncio
async def test_v1_database_is_upgraded_in_place(tmp_path):
    path = str(tmp_path / "v1.db")
    make_v1_db(path)

    db = AlertStorage(path)
    (row,) = await db.get_alerts()
    await db.close()

    assert row["version"] == "2.0" and row["$schema"].endswith("alert.v2.json")
    assert row["migrated_from"] == "1.0"
    assert row["detection"]["rule_matches"] == ["RULE_DNS_TUNNEL_PAYLOAD_DEPTH"]
    assert row["evidence"] == [{"feature": "dns_max_subdomain_depth", "value": 5, "baseline": None, "baseline_source": None}]
    assert row["flow_id"] == "1:d/FP5EW3wiY1vCndhwleRRKHowQ="
    # never measured in v1: left null, not back-filled
    assert row["observability_state"] is None and row["contract_version"] is None

    con = sqlite3.connect(path)
    assert con.execute("PRAGMA user_version").fetchone()[0] == 2
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert con.execute("SELECT schema_version, flow_id FROM alerts").fetchone() == ("2.0", row["flow_id"])
    con.close()


@pytest.mark.asyncio
async def test_v2_columns_are_written_and_counted(tmp_path):
    db = AlertStorage(str(tmp_path / "v2.db"))
    alert = Alert("THREAT_TEST", {}, {}, 0.5, "LOW", {}, {}, flow_id="1:abc=", observability_state="forward_only")
    await db.save_alert(alert)
    await db.save_alert(Alert("THREAT_TEST", {}, {}, 0.5, "LOW", {}, {}))
    assert await db.count_alerts() == 2
    conn = await db.get_connection()
    async with conn.execute("SELECT flow_id, observability_state FROM alerts WHERE alert_id = ?", (alert.alert_id,)) as cur:
        assert await cur.fetchone() == ("1:abc=", "forward_only")
    await db.close()
