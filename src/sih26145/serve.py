"""`sih26145 serve`: replay a capture through the pipeline and serve the API from one process.

Alerts are stored in the API's AlertStorage and pushed to SSE subscribers as they are
produced; /api/v1/metrics reads the running pipeline's counters.
"""

import asyncio
import importlib
import logging
import os
from typing import Optional

import uvicorn

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.storage.database import AlertStorage
from sih26145.streaming import PipelineMetrics, run_stream

log = logging.getLogger("sih26145.serve")
# the module, not the FastAPI object that sih26145.api re-exports under the same name
api = importlib.import_module("sih26145.api.app")


async def serve(pcap: str, speed: Optional[float] = 1.0, host: str = "127.0.0.1", port: int = 8000,
                db: Optional[str] = None, tick: float = 1.0, queue_max: int = 10_000,
                loop: bool = False, pause: float = 30.0) -> None:
    """Replay `pcap` once, or forever with `loop`. Each loop starts from a fresh in-memory alert
    store, hash chain and pipeline (a FeatureStore cannot take timestamps going backwards), holds
    the final picture for `pause` seconds, and sends dashboards an SSE `reset`."""
    if loop and db:
        raise ValueError("--loop starts every replay from an empty in-memory store; it cannot append to --db")
    if db:
        api.storage = AlertStorage(db)
    server = uvicorn.Server(uvicorn.Config(api.app, host=host, port=port, log_level="info"))

    async def replay():
        while not server.started:  # the API lifespan opens the shared storage first
            if server.should_exit:
                return
            await asyncio.sleep(0.05)
        n = 0
        while not server.should_exit:
            n += 1
            if n > 1:
                old, api.storage = api.storage, AlertStorage(":memory:")
                await api.storage.init_db()
                await old.close()
                api.broadcaster.reset({"loop": n})
            pipeline = ThreatDetectionPipeline(storage=api.storage, publish=api.broadcaster.broadcast)
            metrics = api.pipeline_metrics = PipelineMetrics(queue_max)
            api.source = {"capture": os.path.basename(pcap), "speed": speed, "loop": n if loop else None}
            log.info("replaying %s (%s), loop %d", pcap, f"{speed}x real time" if speed else "unthrottled", n)
            await run_stream(pipeline, pcap, speed=speed, tick=tick, metrics=metrics)
            log.info("replay finished: %d flows scored, %d alerts, %d dropped",
                     metrics.flows_scored, metrics.alerts, metrics.drops)
            if not loop:
                return
            await asyncio.sleep(pause)

    await asyncio.gather(server.serve(), replay())
