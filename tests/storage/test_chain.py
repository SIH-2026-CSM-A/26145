"""Tamper-evident alert log: the hash chain verifies untouched, and every edit, deletion or
reordering is caught at the first affected index."""

import hashlib
import json
import sqlite3
import subprocess
import sys

import pytest

from sih26145.alerts.models import Alert
from sih26145.storage import chain
from sih26145.storage.database import AlertStorage


def alert(i: int) -> Alert:
    return Alert(
        threat_class="THREAT_C2_BEACON",
        detector={"name": "c2_beacon_detector", "type": "RULE", "version": "2.1.0"},
        flow={"src_ip": f"10.0.0.{i}", "dst_ip": "203.0.113.66", "dst_port": 443, "protocol": "TCP"},
        confidence=0.8, severity="HIGH",
        detection={"rule_matches": ["RULE_C2_PERIODIC_FLOWS"], "ml_scores": [], "metrics": {"i": i}},
        feature_summary={"total_packets": 3, "total_bytes": 300, "pps": 1.0, "bps": 8.0},
        timestamp=f"2026-09-26T10:00:{i:02d}+00:00", flow_id=f"1:flow{i}", observability_state="bidirectional",
    )


async def make_log(path, n=5):
    db = AlertStorage(str(path))
    for i in range(n):
        await db.save_alert(alert(i))
    await db.close()


def tamper(path, sql, *args):
    con = sqlite3.connect(path)
    con.execute(sql, args)
    con.commit()
    con.close()


@pytest.mark.asyncio
async def test_untouched_log_verifies_and_reopens_on_the_same_chain(tmp_path):
    path = tmp_path / "a.db"
    await make_log(path, 3)
    await make_log(path, 2)  # reopen: the head is read back, the chain continues
    res = chain.verify(str(path))
    assert res["ok"] and res["n"] == 5 and res["rows"] == 5
    con = sqlite3.connect(path)
    rows = con.execute("SELECT prev_hash, record_hash, json_data FROM alerts ORDER BY seq").fetchall()
    assert rows[0][0] == chain.GENESIS == "0" * 64
    assert all(rows[i][0] == rows[i - 1][1] for i in range(1, 5))
    assert json.loads(rows[4][2])["record_hash"] == rows[4][1] == res["head"]


@pytest.mark.asyncio
@pytest.mark.parametrize("sql,args,index", [
    ("UPDATE alerts SET json_data = replace(json_data, '\"HIGH\"', '\"LOW\"') WHERE seq = 2", (), 2),
    ("UPDATE alerts SET json_data = replace(json_data, '203.0.113.66', '203.0.113.67') WHERE seq = 0", (), 0),
    ("UPDATE alerts SET severity = 'LOW' WHERE seq = 3", (), 3),
    ("UPDATE alerts SET campaign_id = 'camp-x' WHERE seq = 1", (), 1),
    ("DELETE FROM alerts WHERE seq = 2", (), 2),
    ("DELETE FROM alerts WHERE seq = 4", (), None),  # the tail: only the exported head can show it
])
async def test_edit_or_delete_is_detected_at_its_index(tmp_path, sql, args, index):
    path = tmp_path / "a.db"
    await make_log(path)
    head = chain.verify(str(path))["head"]
    tamper(path, sql, *args)
    res = chain.verify(str(path))
    if index is None:
        assert res["ok"] and res["head"] != head  # the chain_head.txt export catches a truncated tail
    else:
        assert not res["ok"] and res["first_bad_index"] == index, res


@pytest.mark.asyncio
async def test_reordering_rows_is_detected(tmp_path):
    path = tmp_path / "a.db"
    await make_log(path)
    con = sqlite3.connect(path)
    con.execute("UPDATE alerts SET seq = -1 WHERE seq = 1")
    con.execute("UPDATE alerts SET seq = 1 WHERE seq = 3")
    con.execute("UPDATE alerts SET seq = 3 WHERE seq = -1")
    con.commit()
    con.close()
    res = chain.verify(str(path))
    assert not res["ok"] and res["first_bad_index"] == 1


@pytest.mark.asyncio
async def test_storage_verify_matches_and_export_bundle(tmp_path):
    path = tmp_path / "a.db"
    await make_log(path, 4)
    db = AlertStorage(str(path))
    assert (await db.verify_chain())["ok"]
    await db.close()
    out = tmp_path / "bundle"
    manifest = chain.export(str(path), str(out))
    assert manifest["alerts"] == 4
    assert manifest["alerts_jsonl_sha256"] == hashlib.sha256((out / "alerts.jsonl").read_bytes()).hexdigest()
    assert (out / "chain_head.txt").read_text().strip() == manifest["chain_head"]
    assert manifest["first_timestamp"] == "2026-09-26T10:00:00+00:00"
    sheet = (out / "section63_datasheet.md").read_text()
    assert "not legal advice" in sheet and manifest["alerts_jsonl_sha256"] in sheet
    tamper(path, "UPDATE alerts SET severity = 'LOW' WHERE seq = 0")
    with pytest.raises(ValueError):
        chain.export(str(path), str(tmp_path / "bad"))


@pytest.mark.asyncio
async def test_cli_verify_log_exit_codes(tmp_path):
    path = tmp_path / "a.db"
    await make_log(path, 3)
    cmd = [sys.executable, "-m", "sih26145.cli", "verify-log", "--db", str(path)]
    ok = subprocess.run(cmd, capture_output=True, text=True)
    assert ok.returncode == 0 and "verified" in ok.stdout
    tamper(path, "DELETE FROM alerts WHERE seq = 1")
    bad = subprocess.run(cmd, capture_output=True, text=True)
    assert bad.returncode == 1 and "index 1" in bad.stdout
