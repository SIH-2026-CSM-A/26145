# Isolation: how "nothing goes back" is enforced

The PS asks for detection on a link the enclave only receives from. This page lists what keeps
the sensor from sending anything back, **as it stands today** (2026-09-28). Every check here
names a test or a command that was run. What is a deployment requirement and not enforced by
this code is marked as such.

## 1. The sensor process opens no network socket

| Check | What it proves | Where |
|---|---|---|
| Static scan of the capture path | `ingest/`, `flow/`, `features/`, `detectors/` and `streaming.py` contain no socket creation, no `send*`/`connect`/`bind`/`listen`, no network-client import, and open files read-only | `tests/ingest/test_no_transmit.py` (with a falsification test for each pattern) |
| Runtime audit hook during a replay | A full replay of `demo/demo.pcap` through the real pipeline (detectors, models, correlator, SQLite chain), in a fresh process with a CPython audit hook, creates no `AF_INET`, `AF_INET6` or `AF_PACKET` socket and makes no `connect`/`bind`/`sendto`/`sendmsg` on one. Libraries count too, not only our code. The only socket is asyncio's local `AF_UNIX` self-pipe | `tests/ingest/test_no_outbound_socket.py`; a second test injects one UDP socket and checks that the hook reports it |
| No runtime download | Models, dashboard and the demo capture are baked into the image. Nothing is fetched at start or while running | `DEPLOY.md`; models are hash-checked against `manifest.json` on load |

## 2. Container

**Batch analysis runs with no network at all.** Checked on 2026-09-28 with the demo image:

```bash
docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -e SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 \
  sih26145-demo:latest sh -c 'ls /sys/class/net; sih26145 analyze /app/demo/demo.pcap --db /tmp/a.db; sih26145 verify-log --db /tmp/a.db'
# lo
# Analysis complete. Total alerts generated: 10
# verified: 10 records, chain head …
```

The container's only interface is `lo`. In the same container, `connect(('8.8.8.8', 53))` fails
with `Network is unreachable`.

**The live demo (`serve`) is not `--network none`.** It serves the dashboard and API from the
same process, so it needs a listening port. `docker-compose.yml` hardens it instead:
- `read_only: true` with a tmpfs `/tmp`;
- `cap_drop: ALL` and `no-new-privileges`;
- a non-root user (uid 10001).

Without `CAP_NET_RAW`, the process cannot open a packet socket. Checked: `socket(AF_PACKET,
SOCK_RAW)` in the compose-equivalent container gives `Operation not permitted`. So it cannot
write frames onto any interface. It can still accept connections on its API port, which is the
management side (§4).

## 3. Capture interface: deployment requirements, not enforced by this code

Today the sensor reads capture **files** (classic pcap and pcapng, `ingest/reader.py`). No live
capture interface is implemented. When one is added, the interface must be set up as follows.
This repository does not configure or check any of it:
- The capture NIC has **no IP address** (`ip addr flush dev <if>`) and ARP disabled (`ip link set
  dev <if> arp off`), so the kernel never answers on it. It is in promiscuous mode, receive-only.
- The tap or data diode is **receive-only in hardware**. That is the guarantee; the software
  controls above are a second layer.
- The capture reader uses a read-only socket (`AF_PACKET` receive ring). The container then needs
  `CAP_NET_RAW` for that one socket and nothing else. §1's static scan forbids `send*` on the
  capture path whatever the capabilities are.

## 4. Management side: the API is read-only

- Only `GET` routes under `/api/v1`, each also answering `HEAD` (the SSE stream is GET only).
  Every other method gets 405, including on the static dashboard mount:
  `tests/api/test_readonly_surface.py`.
- There is no write, upload, analyze, reset or configuration route. No CORS middleware: the
  dashboard is served by the same origin.
- SSE (server → browser) is the only push channel, and it only carries alerts.
- **Deployment requirement:** the API listens on the management network, never on the capture
  interface. In the demo both run on one cloud VM that replays a file, so there is no capture
  interface to separate from.

## 5. What this does not claim

- The demo VM is an ordinary cloud VM. There is no hardware diode in the demo; the capture is a
  file.
- The export bundle (`docs/EXPORT.md`) leaves the enclave on one-way media chosen by the
  operator. The sensor has no network path to send it.
