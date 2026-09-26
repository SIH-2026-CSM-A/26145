"""Feature dump: run the real streaming pipeline over a capture and write one row per scored
flow (identity + timestamps + the model input row, at scoring time) as gzip CSV.

Training reads only these files; features are never recomputed any other way.
"""

import csv
import gzip
import time
from typing import Dict

from sih26145.alerts.aggregator import _flow_id
from sih26145.flow.models import FlowRecord
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.streaming import run_stream

ID_COLUMNS = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "community_id", "start_time",
              "last_time", "observability_state", "is_evicted", "is_active_expired"]


def identity(flow: FlowRecord) -> Dict[str, object]:
    key = flow.flow_key
    return {"src_ip": key.src_ip, "src_port": key.src_port, "dst_ip": key.dst_ip, "dst_port": key.dst_port,
            "protocol": key.protocol, "community_id": _flow_id(flow), "start_time": repr(flow.start_time),
            "last_time": repr(flow.last_time), "observability_state": flow.observability_state,
            "is_evicted": int(flow.is_evicted), "is_active_expired": int(flow.is_active_expired)}


async def dump_features(pcap_path: str, out_path: str) -> Dict[str, object]:
    """Replay unthrottled and lossless (the offline path); returns counts for the log."""
    with gzip.open(out_path, "wt", newline="") as fh:
        writer = None

        def sink(flow: FlowRecord, row: Dict[str, float]) -> None:
            nonlocal writer
            if writer is None:
                writer = csv.DictWriter(fh, fieldnames=ID_COLUMNS + list(row))
                writer.writeheader()
            # identity last: the row's dst_port is the FeatureVector's float copy of the same port
            writer.writerow({**{k: repr(v) for k, v in row.items()}, **identity(flow)})

        pipeline = ThreatDetectionPipeline(":memory:", feature_sink=sink, ml=False)
        await pipeline.init()
        start = time.perf_counter()
        try:
            m = await run_stream(pipeline, pcap_path)
        finally:
            await pipeline.storage.close()
    return {"pcap": pcap_path, "out": out_path, "packets": m.packets, "wire_bytes": m.wire_bytes,
            "flows": m.flows_scored, "rule_alerts": m.alerts, "wall_s": round(time.perf_counter() - start, 1)}
