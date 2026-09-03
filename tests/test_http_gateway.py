"""
Integration Tests for HTTP + SSE Gateway and Admin APIs.
"""

import pytest
from fastapi.testclient import TestClient
from fortress.transport.http_sse import create_gateway_app


@pytest.fixture
def client(tmp_path):
    from fortress.config import load_policy
    policy = load_policy()
    policy.audit_ledger.db_path = str(tmp_path / "test_gateway_audit.db")
    app = create_gateway_app(policy)
    return TestClient(app)


def test_dashboard_index_rendered(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "FORTRESS" in res.text
    assert "Deterministic Agent Firewall" in res.text


def test_stats_api(client):
    res = client.get("/api/v1/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "kill_switch_active" in data


def test_audit_verify_api(client):
    res = client.get("/api/v1/audit/verify")
    assert res.status_code == 200
    data = res.json()
    assert "is_valid" in data
    assert data["is_valid"] is True


def test_rest_proxy_tool_call_allowed(client):
    payload = {
        "tool": "read_file",
        "arguments": {"path": "./doc.txt"},
    }
    res = client.post("/v1/proxy/tools/call", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "allowed"


def test_rest_proxy_tool_call_blocked_ssrf(client):
    payload = {
        "tool": "fetch_url",
        "arguments": {"url": "http://169.254.169.254/latest/meta-data/"},
    }
    res = client.post("/v1/proxy/tools/call", json=payload)
    assert res.status_code == 403
    data = res.json()
    assert data["status"] == "blocked"
    assert "metadata" in data["reason"].lower() or "ssrf" in data["reason"].lower()


def test_kill_switch_toggle_api(client):
    res = client.post("/api/v1/admin/killswitch", json={"active": True})
    assert res.status_code == 200
    assert res.json()["kill_switch_active"] is True

    # Check that tool call is now frozen
    payload = {"tool": "read_file", "arguments": {}}
    res_tool = client.post("/v1/proxy/tools/call", json=payload)
    assert res_tool.status_code == 403

    # Disarm
    client.post("/api/v1/admin/killswitch", json={"active": False})
