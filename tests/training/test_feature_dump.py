"""The feature dump holds exactly the rows the runtime models score (train/serve parity)."""

import csv
import gzip
import math

import pytest

from sih26145.features.dump import ID_COLUMNS, dump_features
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils import attack_scenarios as atk
from sih26145.utils.pcap_generator import _write


def same(a: float, b: float) -> bool:
    return (math.isnan(a) and math.isnan(b)) or a == b


@pytest.mark.asyncio
async def test_dump_rows_equal_runtime_model_input(tmp_path):
    pcap, out = str(tmp_path / "c.pcap"), str(tmp_path / "c.csv.gz")
    _write(pcap, atk.c2_beacon() + atk.port_sweep())
    runtime = []
    pipeline = ThreatDetectionPipeline(":memory:", feature_sink=lambda flow, row: runtime.append(row))
    try:
        await pipeline.process_pcap(pcap)
    finally:
        await pipeline.storage.close()

    stats = await dump_features(pcap, out)
    with gzip.open(out, "rt", newline="") as fh:
        dumped = list(csv.DictReader(fh))
    assert stats["flows"] == len(dumped) == len(runtime) > 50
    for got, want in zip(dumped, runtime):
        assert set(got) == set(ID_COLUMNS) | set(want)
        assert all(same(float(got[k]), v) for k, v in want.items())
    assert any(math.isnan(r["pair_iat_cv"]) for r in runtime)  # undefined stays NaN, never 0
    assert all(r["dst_port"].isdigit() for r in dumped)  # identity columns are not overwritten by the row
