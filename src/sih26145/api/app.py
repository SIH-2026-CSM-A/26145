"""FastAPI Application Server for SIH26145."""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional, Set
from pathlib import Path as FsPath

from fastapi import FastAPI, Query, HTTPException, Path
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from sih26145.contract import load_contract

from sih26145.alerts.models import Alert
from sih26145.storage.database import AlertStorage


class AlertBroadcaster:
    """Multi-subscriber SSE broadcaster with disconnect & backpressure handling."""

    def __init__(self, max_queue_size: int = 100):
        self.max_queue_size = max_queue_size
        self._subscribers: Set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        """Create and register a new bounded subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self.max_queue_size)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Remove subscriber queue on disconnect."""
        self._subscribers.discard(q)

    def broadcast(self, alert_dict: Dict[str, Any], event: str = "alert"):
        """Publish an event (an alert dict by default) to all subscribers without blocking."""
        for q in list(self._subscribers):
            try:
                q.put_nowait((event, alert_dict))
            except asyncio.QueueFull:
                # Drop for slow consumers to prevent memory leaks under backpressure
                pass

    def reset(self, info: Dict[str, Any]):
        """Tell dashboards a new replay loop started with an empty store (`serve --loop`)."""
        self.broadcast(info, event="reset")

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global storage & broadcaster instances
import os
db_env = os.getenv("SIH26145_DB_PATH")
storage = AlertStorage(db_env if db_env else ":memory:")
broadcaster = AlertBroadcaster()
# Set by `sih26145 serve` to the running pipeline's PipelineMetrics; None = nothing running.
pipeline_metrics = None
# Set by `sih26145 serve`: what is being replayed, so the dashboard can say so.
source = None
METRIC_FIELDS = ("pipeline_state", "active_flows", "flows_per_sec", "mbps", "packets_per_sec", "rate_window_s",
                 "queue_depth", "queue_max", "drops", "flows_scored", "link_reverse_visibility_w", "alert_latency_ms")


async def publish_alert(alert: Alert) -> str:
    """Save alert to SQLite storage and broadcast to live SSE subscribers."""
    alert_id = await storage.save_alert(alert)
    broadcaster.broadcast(alert.to_dict())
    return alert_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for initializing storage and resources."""
    await storage.init_db()
    yield
    await storage.close()


app = FastAPI(
    title="SIH26145 Cyber Threat Detection API",
    description="REST & SSE Unidirectional Monitoring Services for NTRO",
    version="1.0.0",
    lifespan=lifespan,
)

# No CORS middleware: the dashboard is served from this origin (and Vite dev proxies /api), so
# browsers refuse cross-origin reads. Every route is GET; anything else gets 405.


@app.get("/api/v1/health")
async def get_health():
    """System health status and passive monitoring verification endpoint."""
    return {
        "status": "OK",
        "monitoring": "PASSIVE_READ_ONLY",
        "active": True,
        "engine": "SIH26145 Threat Engine",
    }


@app.get("/api/v1/alerts")
async def get_alerts(
    threat_class: Optional[str] = Query(None, description="Filter by threat class"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000, description="Max alerts to return"),
):
    """Query historical persisted threat alerts from SQLite."""
    if severity and severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise HTTPException(status_code=400, detail="Invalid severity filter value")
        
    alerts = await storage.get_alerts(threat_class=threat_class, severity=severity, limit=limit)
    return {
        "count": len(alerts),
        "alerts": alerts,
    }


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert_by_id(
    alert_id: str = Path(..., description="Canonical alert URN UUID"),
):
    """Retrieve a single threat alert by alert_id.
    
    Classification: IMPLEMENTATION EXTENSION — NOT AN ARCHITECTURE REQUIREMENT.
    """
    alert = await storage.get_alert_by_id(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.get("/api/v1/metrics")
async def get_metrics():
    """Live telemetry from the pipeline running in this process (`sih26145 serve`).

    Rates cover the last ~5 s while running and the whole run once finished
    (`rate_window_s` says which). Every field is null when no pipeline is attached;
    `alert_latency_ms` (flush -> alert published) is null until an alert has been raised.
    """
    snap = pipeline_metrics.snapshot() if pipeline_metrics is not None else dict.fromkeys(METRIC_FIELDS)
    return {
        **snap,
        "telemetry_source": "pipeline" if pipeline_metrics is not None else "not_connected",
        "source": source,
        "total_alerts": await storage.count_alerts(),
        "mode": "PASSIVE_READ_ONLY",
    }


@app.get("/api/v1/contract")
async def get_contract():
    """Feature states from the Unidirectional Feature Contract, for the dashboard's evidence chips."""
    c = load_contract()
    return {"contract_version": c.version,
            "features": {n: {"state": f.state, "reason": f.reason} for n, f in c.features.items()}}


@app.get("/api/v1/campaigns")
async def get_campaigns():
    """Campaigns (correlate.py) with hosts, classes, ATT&CK tactics, time span and refused merges."""
    camps = await storage.get_campaigns()
    return {"count": len(camps), "campaigns": camps}


@app.get("/api/v1/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str = Path(..., max_length=64)):
    alerts = await storage.get_campaign_alerts(campaign_id)
    if not alerts:
        raise HTTPException(status_code=404, detail="Campaign not found")
    summary = next((c for c in await storage.get_campaigns() if c["campaign_id"] == campaign_id), None)
    return {"campaign": summary, "alerts": alerts}


@app.get("/api/v1/hosts/{ip}/timeline")
async def get_host_timeline(ip: str = Path(..., max_length=45)):
    """Observed ATT&CK stages of one internal host, oldest first. History only: no prediction."""
    return {"host": ip, "stages": await storage.host_timeline(ip)}


@app.get("/api/v1/chain/verify")
async def verify_chain():
    """Recompute the alert log's hash chain (storage/chain.py): {ok, n, first_bad_index, reason, head}."""
    return await storage.verify_chain()


@app.get("/api/v1/stream/alerts")
async def stream_alerts():
    """Server-Sent Events (SSE) live event stream pushing alerts to connected clients."""
    subscriber_queue = broadcaster.subscribe()

    async def event_generator():
        try:
            while True:
                try:
                    event, payload = await asyncio.wait_for(subscriber_queue.get(), timeout=15.0)
                    yield {
                        "event": event,
                        "data": json.dumps(payload),
                    }
                except asyncio.TimeoutError:
                    # Periodic heartbeat ping to keep connection active
                    yield {
                        "event": "ping",
                        "data": json.dumps({"type": "heartbeat"}),
                    }
        finally:
            broadcaster.unsubscribe(subscriber_queue)

    return EventSourceResponse(event_generator())


# The built dashboard (dashboard/dist), same origin as the API. Mounted last so /api wins.
DIST = FsPath(__file__).resolve().parents[3] / "dashboard" / "dist"
if (DIST / "index.html").exists():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="dashboard")
