"""
Unit & Integration Tests for Inbound Interception Pipeline.
"""

import pytest
from fortress.config import load_policy
from fortress.core.engine import SecurityEngine
from fortress.core.models import JSONRPCRequest, SecurityContext, SecurityVerdict


@pytest.fixture
def engine():
    policy = load_policy("fortress-policy.yaml")
    return SecurityEngine(policy)


def test_allowed_tool_call(engine):
    req = JSONRPCRequest(
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": "./README.md"}},
    )
    ctx = SecurityContext(session_id="s1", user_id="dev_agent", role="developer")
    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.ALLOW
    assert res.is_allowed
    assert len(res.violations) == 0


def test_global_kill_switch(engine):
    engine.circuit_breaker.set_kill_switch(True)
    req = JSONRPCRequest(
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": "./test.txt"}},
    )
    ctx = SecurityContext(session_id="s_kill", user_id="admin_user", role="admin")
    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.BLOCK
    assert "Global Kill Switch is active" in res.blocked_reason
    engine.circuit_breaker.set_kill_switch(False)


def test_rbac_denied_tool(engine):
    req = JSONRPCRequest(
        method="tools/call",
        params={"name": "delete_database", "arguments": {"db": "prod"}},
    )
    ctx = SecurityContext(session_id="s_rbac", user_id="readonly_bot", role="readonly")
    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.BLOCK
    assert any("forbidden" in v.reason or "not allowed" in v.reason for v in res.violations)


def test_path_traversal_detection(engine):
    traversal_attacks = [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\config\\SAM",
        "nested/../../.ssh/id_rsa",
        "%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "valid_dir/..\x00/id_ed25519",
    ]
    for i, attack in enumerate(traversal_attacks):
        ctx = SecurityContext(session_id=f"s_path_{i}", user_id="dev_agent", role="developer")
        req = JSONRPCRequest(
            method="tools/call",
            params={"name": "read_file", "arguments": {"file_path": attack}},
        )
        res = engine.inspect_inbound(req, ctx)
        assert res.verdict == SecurityVerdict.BLOCK, f"Failed to block traversal: {attack}"
        assert any("path" in v.rule_name for v in res.violations)


def test_ssrf_egress_protection(engine):
    ssrf_attacks = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:5432",
        "http://10.0.0.1/internal/config",
        "http://192.168.1.254",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://0x7f000001/",
        "http://2130706433/",
    ]
    for i, url in enumerate(ssrf_attacks):
        ctx = SecurityContext(session_id=f"s_ssrf_{i}", user_id="dev_agent", role="developer")
        req = JSONRPCRequest(
            method="tools/call",
            params={"name": "fetch_url", "arguments": {"url": url}},
        )
        res = engine.inspect_inbound(req, ctx)
        assert res.verdict == SecurityVerdict.BLOCK, f"Failed to block SSRF URL: {url}"
        assert any("ssrf" in v.rule_name for v in res.violations)


def test_hitl_sensitive_tool(engine):
    req = JSONRPCRequest(
        method="tools/call",
        params={"name": "execute_query", "arguments": {"sql": "UPDATE accounts SET balance = balance + 1000"}},
    )
    ctx = SecurityContext(session_id="s_hitl", user_id="dev_agent", role="developer")
    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.REQUIRE_APPROVAL
    assert res.requires_approval
    assert res.pending_token is not None
    assert res.pending_token.startswith("hitl_tok_")


def test_rate_limiting_and_budget(engine):
    ctx = SecurityContext(session_id="s_rate", user_id="dev_agent", role="developer")
    req = JSONRPCRequest(method="tools/call", params={"name": "read_data", "arguments": {"id": 1}})
    
    for _ in range(60):
        engine.circuit_breaker.record_call(ctx.session_id)

    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.BLOCK
    assert "Rate limit exceeded" in res.blocked_reason


def test_windows_dos_device_name_blocked(engine):
    devices = ["CON", "NUL", "AUX", "COM1.txt", "LPT1"]
    for dev in devices:
        ctx = SecurityContext(session_id=f"s_dev_{dev}", user_id="dev_agent", role="developer")
        req = JSONRPCRequest(method="tools/call", params={"name": "read_file", "arguments": {"path": f"./{dev}"}})
        res = engine.inspect_inbound(req, ctx)
        assert res.verdict == SecurityVerdict.BLOCK
        assert any("reserved_device" in v.rule_name for v in res.violations)


def test_ntfs_alternate_data_stream_blocked(engine):
    ctx = SecurityContext(session_id="s_ads", user_id="dev_agent", role="developer")
    req = JSONRPCRequest(method="tools/call", params={"name": "read_file", "arguments": {"path": "C:/safe/file.txt:hidden_stream"}})
    res = engine.inspect_inbound(req, ctx)
    assert res.verdict == SecurityVerdict.BLOCK
    assert any("alternate_data_stream" in v.rule_name for v in res.violations)


def test_octal_and_ipv6_mapped_ssrf(engine):
    vectors = [
        "http://0177.0.0.1:8080/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::1]:3000/api",
    ]
    for i, vec in enumerate(vectors):
        ctx = SecurityContext(session_id=f"s_oct_{i}", user_id="dev_agent", role="developer")
        req = JSONRPCRequest(method="tools/call", params={"name": "fetch_url", "arguments": {"url": vec}})
        res = engine.inspect_inbound(req, ctx)
        assert res.verdict == SecurityVerdict.BLOCK
        assert any("ssrf" in v.rule_name for v in res.violations)

