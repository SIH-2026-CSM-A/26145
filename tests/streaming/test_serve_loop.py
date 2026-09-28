"""`serve --loop`: each loop replays from an empty store with its own hash chain, and dashboards
get an SSE `reset`; `--loop` refuses to append to a file database."""

import asyncio
import importlib

import pytest

from sih26145.serve import serve
from sih26145.utils.attack_scenarios import port_sweep
from sih26145.utils.pcap_generator import _write

api = importlib.import_module("sih26145.api.app")


@pytest.mark.asyncio
async def test_loop_resets_store_and_notifies(tmp_path):
    pcap = str(tmp_path / "scan.pcap")
    _write(pcap, port_sweep())
    saved = api.storage, api.pipeline_metrics, api.source
    q = api.broadcaster.subscribe()
    task = asyncio.create_task(serve(pcap, None, port=0, loop=True, pause=2.0))
    try:
        events = []
        while len(events) < 5:
            events.append(await asyncio.wait_for(q.get(), timeout=30))
        await asyncio.sleep(0.5)  # loop 2 finishes its (two-alert) replay, then pauses 2 s
        kinds = [e for e, _ in events]
        # loop 1: the fast-lane alert and the flow-lane alert confirming it; reset; loop 2: the
        # same two again, into a fresh store
        assert kinds[:5] == ["alert", "alert", "reset", "alert", "alert"], kinds
        assert events[2][1] == {"loop": 2}
        assert api.source["loop"] >= 2 and api.source["capture"] == "scan.pcap"
        res = await api.storage.verify_chain()
        assert res["ok"] and res["n"] == 2  # this loop's chain only
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        api.broadcaster.unsubscribe(q)
        await api.storage.close()
        api.storage, api.pipeline_metrics, api.source = saved


@pytest.mark.asyncio
async def test_loop_refuses_a_file_database(tmp_path):
    with pytest.raises(ValueError, match="empty in-memory store"):
        await serve("x.pcap", None, loop=True, db=str(tmp_path / "a.db"))
