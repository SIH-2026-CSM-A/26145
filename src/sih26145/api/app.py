"""FastAPI Application Server for SIH26145."""

import asyncio
import json
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional, Set
from fastapi import FastAPI, Query, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

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

    def broadcast(self, alert_dict: Dict[str, Any]):
        """Publish alert dictionary to all active subscribers without blocking."""
        for q in list(self._subscribers):
            try:
                q.put_nowait(alert_dict)
            except asyncio.QueueFull:
                # Drop for slow consumers to prevent memory leaks under backpressure
                pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Global storage & broadcaster instances
import os
db_env = os.getenv("SIH26145_DB_PATH")
storage = AlertStorage(db_env if db_env else ":memory:")
broadcaster = AlertBroadcaster()


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

# Enable CORS for local read-only monitoring dashboard requests (Phase 11 frontend)
# Note: IMPLEMENTATION DECISION — NOT ARCHITECTURE REQUIREMENT
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


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
    """Traffic and flow metrics.

    Only values that are actually measured are returned. The pipeline is not yet wired to
    this process (AUDIT A6), so flow and rate telemetry is null rather than invented.
    """
    return {
        "active_flows": None,
        "packets_per_sec": None,
        "bytes_per_sec": None,
        "link_reverse_visibility": None,
        "telemetry_source": "not_connected",
        "total_alerts": await storage.count_alerts(),
        "mode": "PASSIVE_READ_ONLY",
    }


@app.get("/api/v1/stream/alerts")
async def stream_alerts():
    """Server-Sent Events (SSE) live event stream pushing alerts to connected clients."""
    subscriber_queue = broadcaster.subscribe()

    async def event_generator():
        try:
            while True:
                try:
                    alert_dict = await asyncio.wait_for(subscriber_queue.get(), timeout=15.0)
                    yield {
                        "event": "alert",
                        "data": json.dumps(alert_dict),
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
