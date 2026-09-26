"""Campaign correlation: shared infrastructure never merges, a one-host chain forms one campaign
with its observed stages, ids are deterministic, memory is bounded, and the API serves it."""

import importlib
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from sih26145 import correlate
from sih26145.alerts.models import Alert
from sih26145.correlate import Correlator
from sih26145.features.directional import NetworkPolicy
from sih26145.flow.models import FlowKey, FlowRecord
from sih26145.orchestrator import ThreatDetectionPipeline
from sih26145.utils.attack_scenarios import one_host_chain
from sih26145.utils.pcap_generator import _write

RESOLVER = "10.0.0.53"


@dataclass
class Ctx:
    flow: FlowRecord
    fan_in: dict
    policy: NetworkPolicy = NetworkPolicy.from_env()

    def store_feature(self, name, key):
        assert name == "dst_distinct_srcs_longterm"
        return self.fan_in.get(key, 1.0)


def dns_alert(host, names, t, fan_in):
    flow = FlowRecord(FlowKey(host, RESOLVER, 53, "UDP", 40000), t - 1, t, dns_queries=list(names))
    alert = Alert(threat_class="THREAT_DNS_DGA", detector={"name": "dga_lexical_detector", "type": "RULE"},
                  flow={}, confidence=0.6, severity="MEDIUM", detection={"rule_matches": ["RULE_DGA"]},
                  feature_summary={}, flow_id=f"1:{host}", timestamp=str(t))
    return alert, Ctx(flow, fan_in)


def correlate_all(pairs):
    c = Correlator()
    for alert, ctx in pairs:
        c.assign([alert], c.observe(ctx))
    return [a for a, _ in pairs]


@pytest.mark.parametrize("resolver_fan_in,merged", [(40.0, False), (1.0, True)])
def test_alerts_sharing_only_the_resolver_stay_separate(resolver_fan_in, merged):
    fan = {RESOLVER: resolver_fan_in}
    a, b = correlate_all([dns_alert("192.168.1.80", ["kqxw.com"], 1000.0, fan),
                          dns_alert("192.168.1.81", ["zzvb.net"], 1060.0, fan)])
    assert (a.campaign_id == b.campaign_id) is merged  # control: an ordinary server would merge them
    if not merged:
        (note,) = b.detection["correlation"]["not_merged"]
        assert note["campaign_id"] == a.campaign_id and "shared resolver 10.0.0.53" in note["reason"]
        assert "dst:10.0.0.53" in b.detection["correlation"]["refused_pivots"]


def test_shared_name_still_joins_through_the_resolver():
    fan = {RESOLVER: 40.0}
    a, b = correlate_all([dns_alert("192.168.1.80", ["kqxw.com"], 1000.0, fan),
                          dns_alert("192.168.1.81", ["kqxw.com"], 1060.0, fan)])
    assert a.campaign_id == b.campaign_id  # the same DGA name is a rare pivot of its own
    assert b.detection["correlation"]["joined_on"] == ["name:kqxw.com"]


def test_a_busy_host_is_not_refused_as_infrastructure():
    """Fan-in refusal is for destinations: a workstation that receives replies from many servers
    (high fan-in as a destination) still joins its own alerts through its host pivot."""
    host = "10.9.9.9"  # internal under the default CIDRs
    fan = {host: 60.0}
    a, _ = dns_alert(host, ["x.example"], 1000.0, fan)
    b, _ = dns_alert(host, ["y.example"], 1015.0, fan)
    ctx_a = Ctx(FlowRecord(FlowKey(host, "195.24.233.55", 443, "TCP", 1), 999.0, 1000.0), fan)
    ctx_b = Ctx(FlowRecord(FlowKey("74.125.232.214", host, 50000, "TCP", 443), 1014.0, 1015.0), fan)
    c = Correlator()
    for alert, ctx in ((a, ctx_a), (b, ctx_b)):
        c._observe_fan_in(host, ctx)  # the host is in the top-k fan-in set
        c.assign([alert], c.observe(ctx))
    assert a.campaign_id == b.campaign_id
    assert b.detection["correlation"]["joined_on"] == [f"host:{host}"]


def test_memory_is_bounded():
    c = Correlator()
    for i in range(3000):
        alert, ctx = dns_alert(f"10.{i // 250}.{i % 250}.1", [f"n{i}.com"], 1000.0 + 5000 * i, {})
        ctx.flow.flow_key = FlowKey(ctx.flow.flow_key.src_ip, f"203.0.{i // 250}.{i % 250}", 443, "TCP", 1)
        c.assign([alert], c.observe(ctx))
    assert len(c.campaigns) <= correlate.MAX_CAMPAIGNS and len(c.window) <= correlate.WINDOW
    assert len(c.fan_in) <= correlate.MAX_FAN_IN
    live = {p for camp in c.campaigns.values() for p in camp.pivots}
    assert set(c.index) <= live


async def run_chain(tmp_path, storage=None):
    pcap = str(tmp_path / "chain.pcap")
    _write(pcap, one_host_chain())
    pipeline = ThreatDetectionPipeline(":memory:", storage=storage)
    alerts = await pipeline.process_pcap(pcap)
    return pipeline, alerts


@pytest.mark.asyncio
async def test_one_host_recon_c2_exfil_is_one_campaign_with_three_stages(tmp_path):
    pipeline, alerts = await run_chain(tmp_path)
    try:
        classes = {a.threat_class for a in alerts}
        assert {"THREAT_RECON_PORTSCAN", "THREAT_C2_BEACON", "THREAT_EXFILTRATION"} <= classes
        assert len({a.campaign_id for a in alerts}) == 1, [(a.threat_class, a.campaign_id) for a in alerts]
        stages = await pipeline.storage.host_timeline("192.168.1.66")
        order = list(dict.fromkeys(s["tactic_id"] for s in stages))
        assert order[:3] == ["TA0007", "TA0011", "TA0010"], stages
        assert (await pipeline.storage.verify_chain())["ok"]  # correlation fields are inside the hash
    finally:
        await pipeline.storage.close()


@pytest.mark.asyncio
async def test_campaign_ids_are_deterministic(tmp_path):
    runs = []
    for _ in range(2):
        pipeline, alerts = await run_chain(tmp_path)
        await pipeline.storage.close()
        runs.append([(a.threat_class, a.campaign_id, a.host_stage) for a in alerts])
    assert runs[0] == runs[1]


@pytest.mark.asyncio
async def test_campaign_and_timeline_routes(tmp_path):
    api = importlib.import_module("sih26145.api.app")
    with TestClient(api.app) as client:
        pipeline, alerts = await run_chain(tmp_path, storage=api.storage)
        cid = alerts[0].campaign_id
        camps = client.get("/api/v1/campaigns").json()["campaigns"]
        mine = next(c for c in camps if c["campaign_id"] == cid)
        assert mine["hosts"] == ["192.168.1.66"] and mine["alerts"] == len(alerts)
        assert ["Discovery", "Command and Control", "Exfiltration"] == mine["tactics"][:3]
        detail = client.get(f"/api/v1/campaigns/{cid}").json()
        assert len(detail["alerts"]) == len(alerts)
        assert client.get("/api/v1/campaigns/camp-nope").status_code == 404
        tl = client.get("/api/v1/hosts/192.168.1.66/timeline").json()["stages"]
        assert [s["tactic_id"] for s in tl][:3] == ["TA0007", "TA0011", "TA0010"]
