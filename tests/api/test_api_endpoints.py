"""Unit tests for FastAPI REST endpoints, SQLite storage, and SSE streaming."""

import json
import pytest
from fastapi.testclient import TestClient

from sih26145.alerts.models import Alert
from sih26145.storage.database import AlertStorage
from sih26145.api.app import app, storage, publish_alert, broadcaster


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OK"
    assert data["monitoring"] == "PASSIVE_READ_ONLY"
    assert data["active"] is True


def test_metrics_endpoint(client):
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "active_flows" in data
    assert "total_alerts" in data
    assert data["mode"] == "PASSIVE_READ_ONLY"


def test_alerts_query_and_lookup_endpoints(client):
    # Retrieve alerts
    response = client.get("/api/v1/alerts?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "count" in data
    assert "alerts" in data

    # Test invalid severity filter validation (400 Bad Request)
    bad_resp = client.get("/api/v1/alerts?severity=INVALID_SEVERITY")
    assert bad_resp.status_code == 400

    # Test unknown alert lookup by ID (404 Not Found)
    unknown_resp = client.get("/api/v1/alerts/urn:uuid:00000000-0000-0000-0000-000000000000")
    assert unknown_resp.status_code == 404

    # Test hostile SQL injection string in alert_id path parameter (404 Not Found, safely parameterized)
    sql_injection_id = "urn:uuid:00000000' OR '1'='1"
    sqli_resp = client.get(f"/api/v1/alerts/{sql_injection_id}")
    assert sqli_resp.status_code == 404


def test_rest_input_validation_boundaries(client):
    # Test negative limit
    assert client.get("/api/v1/alerts?limit=-5").status_code == 422
    # Test limit = 0
    assert client.get("/api/v1/alerts?limit=0").status_code == 422
    # Test limit exceeding maximum cap (1000)
    assert client.get("/api/v1/alerts?limit=1500").status_code == 422

    # Test SQL injection string in query parameter (handled safely by parameterized query)
    sqli_param_resp = client.get("/api/v1/alerts?threat_class=' OR 1=1 --")
    assert sqli_param_resp.status_code == 200
    assert sqli_param_resp.json()["count"] == 0


def test_cors_headers_and_security(client):
    # Test allowed local origin (Vite dev server)
    allowed_resp = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert allowed_resp.status_code == 200
    assert allowed_resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert allowed_resp.headers.get("access-control-allow-credentials") is None

    # Test alternate allowed local origin
    alt_allowed_resp = client.get("/api/v1/health", headers={"Origin": "http://127.0.0.1:5173"})
    assert alt_allowed_resp.status_code == 200
    assert alt_allowed_resp.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"

    # Test unapproved external origin
    unauthorized_resp = client.get("/api/v1/health", headers={"Origin": "https://malicious-external-site.com"})
    assert unauthorized_resp.status_code == 200
    assert unauthorized_resp.headers.get("access-control-allow-origin") is None


@pytest.mark.asyncio
async def test_publish_alert_and_sse_broadcasting():
    alert = Alert(
        threat_class="THREAT_DNS_TUNNEL",
        detector={"name": "dns_tunnel_detector", "type": "RULE", "version": "1.0.0"},
        flow={"src_ip": "192.168.1.50", "dst_ip": "10.0.0.53", "dst_port": 53, "protocol": "UDP", "window_start": "2026-09-16T15:00:00Z", "window_end": "2026-09-16T15:00:15Z"},
        confidence=0.95,
        severity="HIGH",
        detection={"rule_matches": ["RULE_DNS_TUNNEL_PAYLOAD_DEPTH"], "ml_scores": [], "metrics": {}},
        feature_summary={"total_packets": 10, "total_bytes": 1000, "pps": 1.0, "bps": 100.0},
    )

    # Subscribe queue 1 & queue 2
    q1 = broadcaster.subscribe()
    q2 = broadcaster.subscribe()
    assert broadcaster.subscriber_count == 2

    # Publish alert
    alert_id = await publish_alert(alert)
    assert alert_id == alert.alert_id

    # Verify both queues receive published alert
    data1 = q1.get_nowait()
    data2 = q2.get_nowait()
    assert data1["alert_id"] == alert.alert_id
    assert data2["alert_id"] == alert.alert_id

    # Unsubscribe queue 1
    broadcaster.unsubscribe(q1)
    assert broadcaster.subscriber_count == 1
    broadcaster.unsubscribe(q2)
    assert broadcaster.subscriber_count == 0


def test_payload_security_boundary_api(client):
    response = client.get("/api/v1/alerts?limit=10")
    assert response.status_code == 200
    json_repr = response.text

    for forbidden_key in ["raw_payload", "payload_bytes", "decrypted_payload", "plaintext_content"]:
        assert forbidden_key not in json_repr



@pytest.mark.asyncio
async def test_sse_payload_is_alert_v2():
    alert = Alert("THREAT_TEST", {}, {"src_ip": "10.0.0.1"}, 0.5, "LOW", {}, {},
                  flow_id="1:abc=", observability_state="reverse_only")
    q = broadcaster.subscribe()
    try:
        await publish_alert(alert)
        payload = q.get_nowait()
    finally:
        broadcaster.unsubscribe(q)
        await storage.close()  # module-global connection must not outlive this test's loop
    assert payload["$schema"].endswith("alert.v2.json")
    assert payload["observability_state"] == "reverse_only"
    assert {"flow_id", "evidence", "contract_version", "model_version", "campaign_id",
            "host_stage", "record_hash", "substitutions"} <= set(payload)
    json.dumps(payload)  # SSE sends it as JSON


def test_metrics_report_only_measured_values(client):
    data = client.get("/api/v1/metrics").json()
    # no pipeline attached to this process: every telemetry field is null, nothing invented
    for field in ("active_flows", "flows_per_sec", "mbps", "packets_per_sec", "queue_depth", "drops",
                  "link_reverse_visibility_w", "alert_latency_ms", "pipeline_state"):
        assert data[field] is None, field
    assert data["telemetry_source"] == "not_connected"
    assert isinstance(data["total_alerts"], int)
