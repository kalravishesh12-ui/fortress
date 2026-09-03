"""
Unit Tests for Cryptographic Tamper-Evident Hash Chain Audit Ledger.
"""

import os
import sqlite3
import pytest
from mcp_shield.audit.ledger import AuditLedger
from mcp_shield.config import AuditLedgerConfig
from mcp_shield.core.models import SecurityVerdict, ViolationRecord, RiskLevel


@pytest.fixture
def temp_ledger(tmp_path):
    db_file = str(tmp_path / "test-audit.db")
    cfg = AuditLedgerConfig(db_path=db_file, hmac_secret_key="test_secret_key")
    return AuditLedger(cfg)


def test_audit_hash_chain_genesis_and_logging(temp_ledger):
    # Log 3 events
    e1 = temp_ledger.log_event(
        session_id="sess_1",
        user_id="user_1",
        tool_name="read_file",
        direction="INBOUND",
        verdict=SecurityVerdict.ALLOW,
        violations=[],
        payload={"path": "file1.txt"},
    )
    assert e1["id"] == 1
    assert e1["entry_hash"] is not None

    e2 = temp_ledger.log_event(
        session_id="sess_1",
        user_id="user_1",
        tool_name="exec_shell",
        direction="INBOUND",
        verdict=SecurityVerdict.BLOCK,
        violations=[ViolationRecord(rule_name="tool_denied", risk_level=RiskLevel.CRITICAL, reason="Forbidden")],
        payload={"command": "rm -rf"},
    )
    assert e2["id"] == 2

    # Verify integrity
    is_valid, errors = temp_ledger.verify_integrity()
    assert is_valid is True
    assert len(errors) == 0


def test_audit_tamper_detection_on_modified_row(temp_ledger):
    # Log 2 events
    temp_ledger.log_event(
        session_id="sess_1",
        user_id="user_1",
        tool_name="read_file",
        direction="INBOUND",
        verdict=SecurityVerdict.ALLOW,
        violations=[],
        payload={"path": "file1.txt"},
    )
    temp_ledger.log_event(
        session_id="sess_1",
        user_id="user_1",
        tool_name="read_file",
        direction="INBOUND",
        verdict=SecurityVerdict.ALLOW,
        violations=[],
        payload={"path": "file2.txt"},
    )

    # Malicious tampering: modify verdict of entry #1 directly in SQLite
    with sqlite3.connect(temp_ledger.config.db_path) as conn:
        conn.execute("UPDATE audit_chain SET verdict = 'BLOCK' WHERE id = 1")
        conn.commit()

    # Verify integrity must fail!
    is_valid, errors = temp_ledger.verify_integrity()
    assert is_valid is False
    assert len(errors) > 0
    assert any("Hash mismatch" in err or "Signature verification failed" in err for err in errors)
