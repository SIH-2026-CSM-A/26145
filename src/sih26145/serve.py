"""`sih26145 serve`: replay a capture through the pipeline and serve the API from one process.

Alerts are stored in the API's AlertStorage and pushed to SSE subscribers as they are
produced; /api/v1/metrics reads the running pipeline's counters.
"""

import asyncio
import importlib
import logging
from typing import Optional

import uvicorn

from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.storage.database import AlertStorage
from sih26145.streaming import PipelineMetrics, run_stream

log = logging.getLogger("sih26145.serve")
# the module, not the FastAPI object that sih26145.api re-exports under the same name
api = importlib.import_module("sih26145.api.app")


async def serve(pcap: str, speed: Optional[float] = 1.0, host: str = "127.0.0.1", port: int = 8000,
                db: Optional[str] = None, tick: float = 1.0, queue_max: int = 10_000) -> None:
    if db:
        api.storage = AlertStorage(db)
    server = uvicorn.Server(uvicorn.Config(api.app, host=host, port=port, log_level="info"))
    pipeline = ThreatDetectionPipeline(storage=api.storage, publish=api.broadcaster.broadcast)
    metrics = api.pipeline_metrics = PipelineMetrics(queue_max)

    async def replay():
        while not server.started:  # the API lifespan opens the shared storage first
            if server.should_exit:
                return
            await asyncio.sleep(0.05)
        pace = f"{speed}x real time" if speed else "unthrottled"
        log.info("replaying %s (%s)", pcap, pace)
        await run_stream(pipeline, pcap, speed=speed, tick=tick, metrics=metrics)
        log.info("replay finished: %d flows scored, %d alerts, %d dropped",
                 metrics.flows_scored, metrics.alerts, metrics.drops)

    await asyncio.gather(server.serve(), replay())
