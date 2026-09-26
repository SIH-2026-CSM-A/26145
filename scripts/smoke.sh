#!/usr/bin/env bash
# Build the dashboard, serve a generated attack capture unthrottled on a free port, run the
# headless Playwright smoke test against it. Usage: scripts/smoke.sh [screenshot-dir]
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
trap 'kill $SERVER 2>/dev/null || true; rm -rf "$TMP"' EXIT
(cd dashboard && npm run build --silent >/dev/null)
uv run python -c "
from sih26145.utils.attack_scenarios import demo_packets, one_host_chain
from sih26145.utils.benign_scenarios import T0
from sih26145.utils.pcap_generator import _write
_write('$TMP/smoke.pcap', demo_packets() + one_host_chain(T0 + 800))"
PORT=$(uv run python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1])")
uv run sih26145 serve "$TMP/smoke.pcap" --unthrottled --port "$PORT" > "$TMP/serve.log" 2>&1 &
SERVER=$!
for _ in $(seq 60); do curl -sf "http://127.0.0.1:$PORT/api/v1/health" >/dev/null && break; sleep 0.5; done
(cd dashboard && node tests/smoke.mjs "http://127.0.0.1:$PORT" "${1:-}")
