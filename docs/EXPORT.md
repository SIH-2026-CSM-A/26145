# Exporting the alert log

The sensor's alert log is a SQLite database with a SHA-256 hash chain over every alert
(`docs/ARCHITECTURE.md` §11). `sih26145 export` turns it into a bundle of plain files that can
leave the enclave on one-way media. The receiving side can check it without the sensor and
without the database.

## Where it goes

`sih26145 export --db PATH --out DIR` writes into `DIR` (created if missing). There is no default
path: the operator names both. The export first recomputes the whole chain (the same check as
`verify-log`). If the chain does not verify, it writes nothing, prints `refused: chain broken at
index N: <reason>` and exits 1.

## What is in the bundle

| File | Format | Contents |
|---|---|---|
| `alerts.jsonl` | UTF-8, one JSON object per line, in chain order (`seq`) | Every alert v2 exactly as hashed: canonical JSON (sorted keys, `","`/`":"` separators, no ASCII escaping). Each object carries its own `record_hash` |
| `chain_head.txt` | One line of 64 hex characters | The `record_hash` of the last alert. It is the only way to detect a truncated tail later |
| `manifest.json` | JSON, indented | `alerts` (count), `first_timestamp` / `last_timestamp` (event time, UTC), `contract_version` and `model_version` (the distinct values in the log), `alerts_jsonl_sha256`, `chain_head`, `chain_genesis` (64 zeros), `hash_algorithm` (`SHA-256`), `exported_at`, `source_db` |
| `section63_datasheet.md` | Markdown | The facts for a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023, laid out as Part A / Part B: the record, its time range, both hash values with the algorithm, the device fields (make/model/serial from DMI when readable, blanks otherwise), the process, and the fields the expert fills in |

## How the pieces fit

- **`verify-log`** is the check on the sensor side. It recomputes the chain from the database and
  also checks that the indexed columns equal the hashed JSON. It prints `verified: N records, chain
  head H`, or `BROKEN at index i of N: <reason>` and exits 1.
- **`export`** runs the same check and writes the bundle only when it passes. So the `chain_head`
  in the bundle is a head that verified at export time.
- **On the receiving side**, the chain can be recomputed from `alerts.jsonl` alone:
  `record_hash(n) = SHA-256(record_hash(n-1) || canonical JSON of alert n without record_hash)`,
  starting from 64 zeros. It must end at `chain_head.txt`. `sha256sum alerts.jsonl` must equal
  `alerts_jsonl_sha256` in the manifest.
- **The Section 63 data sheet is not a certificate** and not legal advice. It collects what an
  operator needs to fill in the certificate form in the Schedule to the Adhiniyam: Part A is signed
  by the person in charge of the device, Part B by an expert who re-computes the hash. Blank
  fields are left for them.

## Worked sequence

Run on 2026-09-28 with the committed demo capture, after the fast lane was added. The hashes below are that run's output. A new
run gives different ones, because `alert_id` is a fresh UUID each time.

```bash
export SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
uv run sih26145 analyze demo/demo.pcap --db /tmp/log.db
# Analysis complete. Total alerts generated: 12   (10 flow-lane + 2 provisional fast-lane)

uv run sih26145 verify-log --db /tmp/log.db
# verified: 12 records, chain head 08edf242…0330f

uv run sih26145 export --db /tmp/log.db --out /tmp/bundle
# exported 12 alerts to /tmp/bundle; alerts.jsonl sha256 f43df07c…e0364

ls /tmp/bundle
# alerts.jsonl  chain_head.txt  manifest.json  section63_datasheet.md

# Receiving side: file hash, then the chain from the JSONL alone
sha256sum /tmp/bundle/alerts.jsonl     # must equal manifest.json alerts_jsonl_sha256
cd /tmp/bundle && uv run --project ~/NewProjects/26145 python -c "
import json; from sih26145.storage.chain import record_hash, GENESIS
prev = GENESIS
for line in open('alerts.jsonl'):
    a = json.loads(line); h = a.pop('record_hash'); assert record_hash(prev, a) == h; prev = h
print(prev == open('chain_head.txt').read().strip())"
# True
```

The Python check above uses only `hashlib` and `json` through `record_hash` (six lines in
`src/sih26145/storage/chain.py`), so it can be rewritten on the receiving side without this
repository.
