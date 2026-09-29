# One-way acceptance evidence: the analysis sends nothing

This page gives three checks an external assessor can re-run to see that the analysis transmits
nothing, plus the acceptance test for a deployed sensor. It was measured on 2026-09-29 on the
development laptop (WSL2, Ubuntu 26.04, Linux 6.18.33.2-microsoft-standard-WSL2, Python 3.13.14),
with `demo/demo.pcap`. Every output below is copied from the run. The raw files are in
`26145-data/oneway-acceptance/`.

All commands run from the repository root with the demo's internal list, as in `docs/ISOLATION.md`.
They call the installed entry point `.venv/bin/sih26145` directly, not through `uv`.

```bash
export SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
```

## Check 1: no-socket audit hook (in-process)

`tests/ingest/test_no_outbound_socket.py` replays `demo/demo.pcap` through the full pipeline
(fast lane, detectors, models, correlator, SQLite chain) in a fresh process. A CPython audit hook
records every `AF_INET`, `AF_INET6` or `AF_PACKET` socket created, and every
`connect`/`bind`/`sendto`/`sendmsg` on one. That covers libraries, not only our code. A second test
injects one UDP socket and checks that the hook reports it, so the hook is known to work.

```bash
uv run pytest -q tests/ingest/test_no_outbound_socket.py
# ..                                                                       [100%]
# 2 passed in 21.38s
```

## Check 2: analysis with no network at all

`unshare -rn` runs the analysis in a new network namespace, as an unprivileged user. The namespace
has only a loopback interface, which is down, so no packet can leave it by any route. Its interface
counters are printed before and after.

```bash
unshare -rn sh -c 'ip -s link; .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/nonet.db; ip -s link'
```

Output (exit 0; the per-alert lines are omitted here and kept in `nonet.txt`):

```
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX:  bytes packets errors dropped  missed   mcast
             0       0      0       0       0       0
    TX:  bytes packets errors dropped carrier collsns
             0       0      0       0       0       0
Analysis complete. Total alerts generated: 12
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX:  bytes packets errors dropped  missed   mcast
             0       0      0       0       0       0
    TX:  bytes packets errors dropped carrier collsns
             0       0      0       0       0       0
```

**Does it produce the same alerts as a normal run?** Two normal runs were made for comparison:

```bash
.venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/norm1.db
.venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/norm2.db
.venv/bin/sih26145 verify-log --db /tmp/norm1.db    # and norm2, nonet
uv run python scripts/baseline.py digest /tmp/norm1.db /tmp/norm2.db /tmp/nonet.db
```

| Run | Alerts | `verify-log` | Chain head (last `record_hash`) | Content digest, sorted | Content digest, storage order |
|---|---|---|---|---|---|
| normal 1 | 12 | verified: 12 records | `0844c166…` | `5e0315d42d81…` | `0ec4a132…` |
| normal 2 | 12 | verified: 12 records | `25de415c…` | `5e0315d42d81…` | `ade1ae1c…` |
| no network | 12 | verified: 12 records | `36b6d36d…` | `5e0315d42d81…` | `4c0d521c…` |

- **The record hashes do not match, and they cannot, not even between the two normal runs.**
  None of the 12 record hashes is shared by any two runs. Each alert gets a random `alert_id`
  (`uuid4`, `src/sih26145/alerts/models.py`), `record_hash` covers the whole alert including it, and
  each hash chains to the one before.
- **The content is identical in all three runs.** The content digest is a sha256 over each alert's
  canonical JSON (`storage/chain.canonical_json`) with the three fields that differ between any two
  runs removed:
  - `alert_id`;
  - `record_hash`;
  - `confirms`, which holds the `alert_id` of the provisional alert it confirms.

  The sorted digest, which is independent of storage order, is the same for all three runs:
  `5e0315d42d811dd0e3a07699be3f9eb3e580fa3469124317007d88bc6f80115b`.
- **The storage order differs between runs**, including between the two normal ones. The
  provisional fast-lane SYN-flood alert is published by the producer as soon as it reads the flood.
  The consumer is then still scoring earlier flows, so that alert lands in position 4, 5 or 6
  depending on scheduling. The other 11 alerts are in the same relative order in all three runs.

**Result: the no-network run raised the same 12 alerts as the normal runs, with identical
content.**

## Check 3: network system calls of the analysis process

Your exact command. `-f` follows every thread and child:

```bash
strace -f -qq -e trace=%network -c .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/st.db
```

```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 51.65    0.000580           9        61           sendto
 44.79    0.000503           4       122        61 recvfrom
  1.78    0.000020          10         2           getsockname
  1.78    0.000020          20         1           socketpair
------ ----------- ----------- --------- --------- ----------------
100.00    0.001123           6       186        61 total
```

**Result:**
- `socket`: 0, `connect`: 0, `bind`: 0, `sendmsg`: 0.
- `sendto`: **61**, `recvfrom`: 122, `socketpair`: 1, `getsockname`: 2.

The expected result was "0 socket, connect and send calls". **The `sendto` count is not 0**, so
every one of these calls was traced to its socket:

```bash
strace -f -qq -yy -e trace=%network -o strace-calls.txt .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/st2.db
```

With `-yy`, strace prints each descriptor's socket type and endpoints:
- **All 186 calls are on one socket pair**, created by the single `socketpair(AF_UNIX,
  SOCK_STREAM|SOCK_CLOEXEC, 0, [6<UNIX-STREAM:[11142794->11142795]>, 7<UNIX-STREAM:[…]>])`.
- No line of `strace-calls.txt` names any other socket.
- Every `sendto` writes one byte, `"\0"`.

That pair is asyncio's self-pipe. `asyncio/selector_events.py` line 120 creates it with
`socket.socketpair()`: a pair of connected local sockets with no address, which cannot reach any
network interface. A bare `asyncio.run(asyncio.sleep(0))` makes the same `socketpair` and two
`getsockname` calls. Each `sendto` of `"\0"` is asyncio waking its own event loop
(`_write_to_self`). aiosqlite's database thread does this when a write completes
(`call_soon_threadsafe`). Each `recvfrom` drains it, and half of them return `EAGAIN` once it is
empty. This is the same local socket that check 1 allows (`AF_UNIX`), for the same reason.

**No `AF_INET`, `AF_INET6`, `AF_PACKET` or `AF_NETLINK` socket was created, and nothing was sent
anywhere except the one byte asyncio passes to itself inside the process.**

## Deployment acceptance test: capture-NIC transmit counter

The checks above cover the software. On a deployed sensor, the assessor also reads the capture
interface's own transmit counters around a run. This needs the real capture NIC; it was **not run
here**, since the development machine reads files and has no capture interface.

```bash
IF=<capture interface>
ip addr show dev "$IF"                # pass: no inet/inet6 address (docs/ISOLATION.md §3)
ip link show dev "$IF"                # pass: NOARP and PROMISC in the flags
ip -s link show dev "$IF" > tx-before.txt
# ... run the sensor over the observation window (e.g. 24 h of live traffic) ...
ip -s link show dev "$IF" > tx-after.txt
diff <(grep -A1 'TX:' tx-before.txt) <(grep -A1 'TX:' tx-after.txt)   # pass: no output
```

**Pass:** the TX `bytes` and `packets` counters are identical before and after, while the RX
counters grew. This reads the NIC's own counters, so it covers anything on the host, not only the
sensor process. The receive-only tap or data diode (docs/ISOLATION.md §3) remains the guarantee;
this test shows that the software side keeps it.

## Reproduce everything on this page

```bash
export SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
uv run pytest -q tests/ingest/test_no_outbound_socket.py
.venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/norm1.db
.venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/norm2.db
unshare -rn sh -c 'ip -s link; .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/nonet.db; ip -s link'
for d in norm1 norm2 nonet; do .venv/bin/sih26145 verify-log --db /tmp/$d.db; done
uv run python scripts/baseline.py digest /tmp/norm1.db /tmp/norm2.db /tmp/nonet.db
strace -f -qq -e trace=%network -c .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/st.db
strace -f -qq -yy -e trace=%network -o strace-calls.txt .venv/bin/sih26145 analyze demo/demo.pcap --db /tmp/st2.db
```

Use fresh database paths: `analyze` adds its alerts to an existing database rather than replacing it (the storage layer has no delete).
