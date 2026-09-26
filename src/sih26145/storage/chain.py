"""Tamper-evident alert log: a SHA-256 hash chain over the stored alerts.

record_hash(n) = SHA-256( prev_hash(n) || canonical JSON of alert n without record_hash ), where
prev_hash(n) = record_hash(n-1), and prev_hash(0) = GENESIS (64 zeros). Both hashes are hex text,
and the concatenation hashes the ASCII of prev_hash, then the UTF-8 of the JSON. Canonical JSON
means sorted keys, no whitespace (separators "," and ":"), and non-ASCII kept as UTF-8.

Editing any stored field, deleting a row or reordering rows changes a recomputed hash, and
`verify_rows` reports the first index that no longer matches. The chain proves integrity since
the row it starts from. It cannot prove a whole log was not replaced: keep the exported
chain_head.txt somewhere separate.
"""

import hashlib
import json
import os
import platform
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

GENESIS = "0" * 64
ALGORITHM = "SHA-256"
# Indexed columns duplicated from the JSON: an edit to either copy is detected.
COLUMNS = ("alert_id", "timestamp", "threat_class", "severity", "confidence", "flow_id", "observability_state",
           "campaign_id")
ROW_SQL = f"SELECT seq, prev_hash, record_hash, json_data, {', '.join(COLUMNS)} FROM alerts ORDER BY seq"


def canonical_json(d: Dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(prev_hash: str, alert: Dict[str, Any]) -> str:
    body = {k: v for k, v in alert.items() if k != "record_hash"}
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_json(body).encode("utf-8")).hexdigest()


def verify_rows(rows: Iterable[Tuple]) -> Dict[str, Any]:
    """rows as ROW_SQL returns them. {ok, n, first_bad_index, reason, head}."""
    prev, n = GENESIS, 0
    for i, (seq, prev_hash, stored, raw, *cols) in enumerate(rows):
        n = i + 1
        try:
            alert = json.loads(raw)
        except (TypeError, ValueError):
            return _bad(i, n, "alert JSON unreadable")
        if seq != i:
            return _bad(i, n, f"sequence gap: expected {i}, found {seq}")
        if prev_hash != prev:
            return _bad(i, n, "prev_hash does not match the previous record")
        if record_hash(prev, alert) != stored or alert.get("record_hash") != stored:
            return _bad(i, n, "record_hash does not match the record's content")
        for name, value in zip(COLUMNS, cols):
            if name == "confidence":
                if value is None or abs(float(value) - float(alert.get(name) or 0)) > 1e-9:
                    return _bad(i, n, "column confidence differs from the hashed record")
            elif value != alert.get(name):
                return _bad(i, n, f"column {name} differs from the hashed record")
        prev = stored
    return {"ok": True, "n": n, "first_bad_index": None, "reason": None, "head": prev}


def _bad(i: int, n: int, reason: str) -> Dict[str, Any]:
    return {"ok": False, "n": n, "first_bad_index": i, "reason": reason, "head": None}


def _connect(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        raise FileNotFoundError(db_path)
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def verify(db_path: str) -> Dict[str, Any]:
    with _connect(db_path) as conn:
        res = verify_rows(conn.execute(ROW_SQL))
    # verify_rows stops at the first break; count the whole table for the report
    with _connect(db_path) as conn:
        res["rows"] = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return res


def export(db_path: str, out_dir: str) -> Dict[str, Any]:
    """One-way transfer bundle: alerts.jsonl, chain_head.txt, manifest.json, section63_datasheet.md.
    Refuses to export a log whose chain does not verify."""
    check = verify(db_path)
    if not check["ok"]:
        raise ValueError(f"chain broken at index {check['first_bad_index']}: {check['reason']}")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sha, count, first, last = hashlib.sha256(), 0, None, None
    contracts, models = set(), set()
    with _connect(db_path) as conn, open(out / "alerts.jsonl", "w", encoding="utf-8") as fh:
        for (raw,) in conn.execute("SELECT json_data FROM alerts ORDER BY seq"):
            alert = json.loads(raw)
            line = canonical_json(alert) + "\n"
            fh.write(line)
            sha.update(line.encode("utf-8"))
            count += 1
            ts = alert.get("timestamp")
            first = ts if first is None or (ts and ts < first) else first
            last = ts if last is None or (ts and ts > last) else last
            contracts.add(alert.get("contract_version"))
            models.add(alert.get("model_version"))
    (out / "chain_head.txt").write_text(check["head"] + "\n")
    manifest = {
        "alerts": count, "first_timestamp": first, "last_timestamp": last,
        "contract_version": sorted(v for v in contracts if v), "model_version": sorted(v for v in models if v),
        "alerts_jsonl_sha256": sha.hexdigest(), "chain_head": check["head"], "chain_genesis": GENESIS,
        "hash_algorithm": ALGORITHM, "exported_at": datetime.now(timezone.utc).isoformat(),
        "source_db": os.path.abspath(db_path),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "section63_datasheet.md").write_text(datasheet(manifest))
    return manifest


def _dmi(name: str) -> Optional[str]:
    try:
        return Path(f"/sys/class/dmi/id/{name}").read_text().strip() or None
    except OSError:
        return None


def datasheet(m: Dict[str, Any]) -> str:
    blank = "____________________"
    vendor, product, serial = _dmi("sys_vendor"), _dmi("product_name"), _dmi("product_serial")
    return f"""# Data sheet for a Section 63 certificate (Bharatiya Sakshya Adhiniyam, 2023)

**This is a data sheet, not legal advice and not a certificate.** It collects the facts an
operator needs to fill in the certificate in the Schedule to the Adhiniyam for this alert log.
The certificate itself is the form in the Schedule. Part A is signed by the person in charge of
the device or activities, and Part B by an expert. It must be completed on that form, whose wording
should be checked against the Gazette text. This sheet follows that structure: Part A covers the
record, how it was produced, the device particulars and the hash value with its algorithm; Part B
covers the expert's check of the hash. Blank fields are for the operator.

## Electronic record
| Field | Value |
|---|---|
| Record | SIH26145 alert log export: `alerts.jsonl` ({m['alerts']} alerts, one JSON object per line) |
| Time range of the alerts (event time, UTC) | {m['first_timestamp']} to {m['last_timestamp']} |
| Exported at (UTC) | {m['exported_at']} |
| Source database | `{m['source_db']}` |
| Contract / model versions | {', '.join(m['contract_version']) or '-'} / {', '.join(m['model_version']) or '-'} |

## Hash values
| Field | Value |
|---|---|
| Algorithm | {m['hash_algorithm']} |
| Hash of `alerts.jsonl` | `{m['alerts_jsonl_sha256']}` |
| Hash-chain head (`chain_head.txt`) | `{m['chain_head']}` |
| Chain genesis | `{m['chain_genesis']}` (64 zeros) |
| How to re-check | `sha256sum alerts.jsonl`; `sih26145 verify-log --db <database>` |

## Device that produced the record
| Field | Value |
|---|---|
| Make | {vendor or blank} |
| Model | {product or blank} |
| Serial number | {serial or blank} |
| Operating system | {platform.system()} {platform.release()} |
| Other identifier (MAC / UID / asset tag) | {blank} |
| Device in the lawful control of | {blank} |
| Device operating properly during the period (or details of any fault) | {blank} |

## Process
The sensor received packets from a passive, receive-only tap or SPAN port. It never transmits onto
the monitored link. It assembled flows, scored them with the rule detectors and models named by
the versions above, and wrote each alert to a SQLite database. Each alert is linked to the
previous one by the SHA-256 hash chain described in `docs/ARCHITECTURE.md` §11. The export
recomputed the chain before writing this bundle, and it verified.

## Part B: facts for the expert
| Field | Value |
|---|---|
| Hash algorithm the expert re-computed | {blank} (expected: {m['hash_algorithm']}) |
| Hash value the expert obtained for `alerts.jsonl` | {blank} (expected: `{m['alerts_jsonl_sha256']}`) |
| `sih26145 verify-log` result on the source database | {blank} |

## Signatures
| | Name | Designation | Date | Signature |
|---|---|---|---|---|
| Part A: person in charge of the device or activities | {blank} | {blank} | {blank} | {blank} |
| Part B: expert | {blank} | {blank} | {blank} | {blank} |
"""
