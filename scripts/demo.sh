#!/usr/bin/env bash
# Watch it work: replay the committed demo capture (demo/demo.pcap) through the real pipeline
# and open the dashboard on http://127.0.0.1:8000. SPEED defaults to 5x (11 min -> ~2 min).
set -euo pipefail
cd "$(dirname "$0")/.."
SPEED=${SPEED:-5}
PORT=${PORT:-8000}
[ -f dashboard/dist/index.html ] || (cd dashboard && npm ci --no-audit --no-fund && npm run build)
export SIH26145_INTERNAL_CIDRS=147.32.0.0/16,10.0.0.0/8,192.168.0.0/16,172.16.0.0/12
echo "Dashboard: http://127.0.0.1:${PORT}  (replaying demo/demo.pcap at ${SPEED}x, looping)"
exec uv run sih26145 serve demo/demo.pcap --speed "$SPEED" --loop --host 127.0.0.1 --port "$PORT"
