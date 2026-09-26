"""Unit tests for SQLite storage engine and SQL injection defenses."""

import os
import json
import pytest

from sih26145.alerts.models import Alert
from sih26145.storage.database import AlertStorage


@pytest.mark.asyncio
async def test_sqlite_save_and_retrieve_round_trip():
    db = AlertStorage(":memory:")
    await db.init_db()

    alert = Alert(
        threat_class="THREAT_DNS_TUNNEL",
        detector={"name": "dns_tunnel_detector", "type": "RULE", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.50", "dst_ip": "10.0.0.53", "dst_port": 53, "protocol": "UDP", "window_start": "2026-09-16T15:00:00Z", "window_end": "2026-09-16T15:00:15Z"},
        confidence=0.95,
        severity="HIGH",
        detection={"rule_matches": ["RULE_DNS_TUNNEL_PAYLOAD_DEPTH"], "ml_scores": [], "metrics": {"depth": 5}},
        feature_summary={"total_packets": 10, "total_bytes": 1000, "pps": 1.0, "bps": 100.0},
    )

    alert_id = await db.save_alert(alert)
    assert alert_id == alert.alert_id

    # Test retrieval by filter
    records = await db.get_alerts(threat_class="THREAT_DNS_TUNNEL")
    assert len(records) == 1
    assert records[0]["alert_id"] == alert.alert_id
    assert records[0]["threat_class"] == "THREAT_DNS_TUNNEL"
    assert records[0]["confidence"] == 0.95

    # Test single alert lookup by ID
    single_record = await db.get_alert_by_id(alert_id)
    assert single_record is not None
    assert single_record["alert_id"] == alert.alert_id
    assert single_record["detection"]["metrics"]["depth"] == 5

    await db.close()


@pytest.mark.asyncio
async def test_sqlite_sql_injection_defense():
    db = AlertStorage(":memory:")
    await db.init_db()

    alert = Alert(
        threat_class="THREAT_DDOS_VOLUME",
        detector={"name": "ddos_volume_detector", "type": "RULE", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"},
        confidence=0.90,
        severity="CRITICAL",
        detection={},
        feature_summary={"total_packets": 100, "total_bytes": 10000, "pps": 10.0, "bps": 1000.0},
    )
    await db.save_alert(alert)

    # Test malicious SQL injection string filters
    malicious_inputs = [
        "' OR 1=1 --",
        "\"; DROP TABLE alerts; --",
        "THREAT_DDOS_VOLUME' UNION SELECT * FROM alerts --",
        "<script>alert(1)</script>",
    ]

    for attack in malicious_inputs:
        records = await db.get_alerts(threat_class=attack)
        assert isinstance(records, list)
        assert len(records) == 0

        single = await db.get_alert_by_id(attack)
        assert single is None

    # Verify table integrity after injection attempts
    valid_records = await db.get_alerts(threat_class="THREAT_DDOS_VOLUME")
    assert len(valid_records) == 1

    await db.close()


@pytest.mark.asyncio
async def test_sqlite_duplicate_alert_id_is_refused_not_replaced():
    """A chained record is never overwritten (storage/chain.py): a second save with the same
    alert_id raises, and the first record and the chain stay intact."""
    import sqlite3
    db = AlertStorage(":memory:")
    await db.init_db()

    alert1 = Alert(
        threat_class="THREAT_RECON_PORTSCAN",
        detector={"name": "recon_portscan_detector", "type": "RULE", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"},
        confidence=0.85,
        severity="MEDIUM",
        detection={"attempt": 1},
        feature_summary={"total_packets": 5, "total_bytes": 500, "pps": 1.0, "bps": 100.0},
    )

    alert_id = await db.save_alert(alert1)

    # Modify confidence and save again with same alert_id
    alert2 = Alert(
        threat_class="THREAT_RECON_PORTSCAN",
        detector={"name": "recon_portscan_detector", "type": "RULE", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"},
        confidence=0.99,
        severity="HIGH",
        detection={"attempt": 2},
        feature_summary={"total_packets": 5, "total_bytes": 500, "pps": 1.0, "bps": 100.0},
        alert_id=alert_id,
    )

    with pytest.raises(sqlite3.IntegrityError):
        await db.save_alert(alert2)

    records = await db.get_alerts(threat_class="THREAT_RECON_PORTSCAN")
    assert len(records) == 1
    assert records[0]["confidence"] == 0.85
    assert records[0]["severity"] == "MEDIUM"
    assert records[0]["detection"]["attempt"] == 1
    assert (await db.verify_chain())["ok"]

    await db.close()


@pytest.mark.asyncio
async def test_sqlite_filtering_and_pagination():
    db = AlertStorage(":memory:")
    await db.init_db()

    # Save multiple alerts with different threat classes & severities
    for i in range(15):
        severity = "HIGH" if i % 2 == 0 else "MEDIUM"
        threat_class = "THREAT_EXFILTRATION" if i < 10 else "THREAT_C2_BEACON"
        alert = Alert(
            threat_class=threat_class,
            detector={"name": "test", "type": "RULE", "version": "1.0.0"},
            flow={"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "protocol": "TCP"},
            confidence=0.80,
            severity=severity,
            detection={"idx": i},
            feature_summary={"total_packets": 10, "total_bytes": 1000, "pps": 1.0, "bps": 100.0},
        )
        await db.save_alert(alert)

    # Test threat_class filter
    exfil_alerts = await db.get_alerts(threat_class="THREAT_EXFILTRATION", limit=100)
    assert len(exfil_alerts) == 10

    # Test severity filter
    high_alerts = await db.get_alerts(severity="HIGH", limit=100)
    assert len(high_alerts) == 8

    # Test limit pagination
    limited_alerts = await db.get_alerts(limit=5)
    assert len(limited_alerts) == 5

    await db.close()
