"""Read-only endpoints the session-6 dashboard reads, and HEAD on every GET route (curl -I)."""

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from sih26145.alerts.models import Alert
from sih26145.api.app import app, publish_alert
from tests.api.test_readonly_surface import concrete


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _alert(cls: str) -> Alert:
    return Alert(cls, {}, {"src_ip": "10.0.0.1", "dst_ip": "203.0.113.5"}, 0.5, "LOW", {}, {},
                 flow_id="1:abc=", observability_state="forward_only")


def test_head_answers_on_every_get_route_except_the_stream(client):
    for r in app.routes:
        if not isinstance(r, APIRoute) or r.path == "/api/v1/stream/alerts":
            continue
        path = concrete(r.path)
        get = client.get(path, params={"alert_id": "x"} if "blocks" in path else None)
        head = client.head(path, params={"alert_id": "x"} if "blocks" in path else None)
        assert head.status_code == get.status_code, f"HEAD {path} -> {head.status_code}, GET -> {get.status_code}"
        assert head.content == b""
    assert client.head("/api/v1/health").status_code == 200


def test_class_stats_count_the_whole_log(client):
    before = client.get("/api/v1/stats/classes").json()["classes"].get("THREAT_TEST_STATS", {}).get("count", 0)
    ids = [client.portal.call(publish_alert, _alert("THREAT_TEST_STATS")) for _ in range(3)]
    row = client.get("/api/v1/stats/classes").json()["classes"]["THREAT_TEST_STATS"]
    assert row["count"] == before + 3 and row["last_seen"]
    assert len(set(ids)) == 3
    fast = _alert("THREAT_TEST_STATS")
    fast.provisional = True
    client.portal.call(publish_alert, fast)
    row = client.get("/api/v1/stats/classes").json()["classes"]["THREAT_TEST_STATS"]
    assert row["count"] == before + 3 and row["provisional"] >= 1  # fast-lane alerts are counted apart


def test_chain_blocks_are_the_neighbouring_links(client):
    ids = [client.portal.call(publish_alert, _alert("THREAT_TEST_CHAIN")) for _ in range(5)]
    res = client.get("/api/v1/chain/blocks", params={"alert_id": ids[2], "around": 2}).json()
    blocks = res["blocks"]
    assert [b["alert_id"] for b in blocks] == ids
    assert [b["seq"] for b in blocks] == list(range(res["seq"] - 2, res["seq"] + 3))
    for prev, cur in zip(blocks, blocks[1:]):
        assert cur["prev_hash"] == prev["record_hash"]  # the drawing's links are the real chain
    assert set(blocks[0]) == {"seq", "alert_id", "threat_class", "prev_hash", "record_hash"}  # hashes only, no flow data


def test_chain_blocks_unknown_alert_is_404(client):
    assert client.get("/api/v1/chain/blocks", params={"alert_id": "urn:uuid:nope"}).status_code == 404
    assert client.get("/api/v1/chain/blocks", params={"alert_id": "x", "around": 9}).status_code == 422
