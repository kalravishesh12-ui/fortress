"""
Cryptographic Tamper-Evident Hash Chain Audit Ledger (SQLite + HMAC-SHA256).
"""

from __future__ import annotations
import hashlib
import hmac
import json
import sqlite3
import time
import threading
from typing import Any, Dict, List, Optional, Tuple
from fortress.config import AuditLedgerConfig
from fortress.core.models import SecurityVerdict, ViolationRecord


class AuditLedger:
    """
    Append-only, mathematically verifiable hash-chained audit ledger.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, config: AuditLedgerConfig):
        self.config = config
        self._write_lock = threading.Lock()
        self._write_conn: Optional[sqlite3.Connection] = None
        self._last_entry_hash: Optional[str] = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.config.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA cache_size=-16000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _get_write_connection(self) -> sqlite3.Connection:
        if self._write_conn is None:
            self._write_conn = sqlite3.connect(
                self.config.db_path,
                timeout=30.0,
                check_same_thread=False,
                isolation_level=None,  # Manual transaction control (BEGIN EXCLUSIVE / COMMIT)
            )
            self._write_conn.row_factory = sqlite3.Row
            self._write_conn.execute("PRAGMA journal_mode=WAL;")
            self._write_conn.execute("PRAGMA synchronous=NORMAL;")
            self._write_conn.execute("PRAGMA temp_store=MEMORY;")
            self._write_conn.execute("PRAGMA cache_size=-16000;")
            self._write_conn.execute("PRAGMA foreign_keys=ON;")
            self._write_conn.execute("PRAGMA busy_timeout=30000;")
        return self._write_conn

    def _init_db(self) -> None:
        if not self.config.enabled:
            return

        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    violations_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    signature TEXT NOT NULL
                );
            """)
            cursor = conn.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            self._last_entry_hash = row["entry_hash"] if row else self.GENESIS_HASH
            conn.commit()

    def _compute_payload_hash(self, payload: Any) -> str:
        serialized = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _compute_entry_hash(
        self,
        prev_hash: str,
        timestamp: float,
        session_id: str,
        user_id: str,
        tool_name: str,
        direction: str,
        verdict: str,
        payload_hash: str,
    ) -> str:
        data_block = f"{prev_hash}|{timestamp:.6f}|{session_id}|{user_id}|{tool_name}|{direction}|{verdict}|{payload_hash}"
        return hashlib.sha256(data_block.encode("utf-8")).hexdigest()

    def _sign_hash(self, entry_hash: str) -> str:
        secret = self.config.hmac_secret_key.encode("utf-8")
        return hmac.new(secret, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def log_event(
        self,
        session_id: str,
        user_id: str,
        tool_name: str,
        direction: str,
        verdict: SecurityVerdict,
        violations: List[ViolationRecord],
        payload: Any,
    ) -> Dict[str, Any]:
        if not self.config.enabled:
            return {}

        now = time.time()
        payload_hash = self._compute_payload_hash(payload)
        violations_data = [v.model_dump() for v in violations]
        violations_json = json.dumps(violations_data)

        with self._write_lock:
            conn = self._get_write_connection()
            conn.execute("BEGIN EXCLUSIVE;")
            try:
                cursor = conn.execute("SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                prev_hash = row["entry_hash"] if row else self.GENESIS_HASH

                entry_hash = self._compute_entry_hash(
                    prev_hash=prev_hash,
                    timestamp=now,
                    session_id=session_id,
                    user_id=user_id,
                    tool_name=tool_name,
                    direction=direction,
                    verdict=verdict.value,
                    payload_hash=payload_hash,
                )
                signature = self._sign_hash(entry_hash)

                cursor = conn.execute("""
                    INSERT INTO audit_chain (
                        timestamp, session_id, user_id, tool_name, direction,
                        verdict, violations_json, payload_hash, prev_hash, entry_hash, signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    now, session_id, user_id, tool_name, direction,
                    verdict.value, violations_json, payload_hash, prev_hash, entry_hash, signature
                ))
                entry_id = cursor.lastrowid
                conn.execute("COMMIT;")
                self._last_entry_hash = entry_hash
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

        return {
            "id": entry_id,
            "timestamp": now,
            "entry_hash": entry_hash,
            "signature": signature,
        }

    def verify_integrity(self) -> Tuple[bool, List[str]]:
        if not self.config.enabled:
            return True, ["Audit ledger is disabled."]

        # Flush any pending writes on write connection
        with self._write_lock:
            if self._write_conn is not None:
                try:
                    self._write_conn.execute("COMMIT;")
                except Exception:
                    pass

        errors: List[str] = []
        expected_prev_hash = self.GENESIS_HASH

        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT id, timestamp, session_id, user_id, tool_name, direction,
                       verdict, payload_hash, prev_hash, entry_hash, signature
                FROM audit_chain ORDER BY id ASC
            """)
            rows = cursor.fetchall()

            for row in rows:
                row_id = row["id"]
                if row["prev_hash"] != expected_prev_hash:
                    errors.append(
                        f"Entry #{row_id}: Broken hash chain! prev_hash '{row['prev_hash']}' != expected '{expected_prev_hash}'"
                    )

                recomputed_hash = self._compute_entry_hash(
                    prev_hash=row["prev_hash"],
                    timestamp=row["timestamp"],
                    session_id=row["session_id"],
                    user_id=row["user_id"],
                    tool_name=row["tool_name"],
                    direction=row["direction"],
                    verdict=row["verdict"],
                    payload_hash=row["payload_hash"],
                )
                if recomputed_hash != row["entry_hash"]:
                    errors.append(
                        f"Entry #{row_id}: Hash mismatch! Computed '{recomputed_hash}' != stored '{row['entry_hash']}'"
                    )

                recomputed_sig = self._sign_hash(row["entry_hash"])
                if recomputed_sig != row["signature"]:
                    errors.append(
                        f"Entry #{row_id}: Signature verification failed! Tampered row data."
                    )

                expected_prev_hash = row["entry_hash"]

        return len(errors) == 0, errors

    def get_recent_entries(
        self,
        limit: int = 50,
        offset: int = 0,
        tool_name: Optional[str] = None,
        verdict: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        if not self.config.enabled:
            return []

        query = "SELECT * FROM audit_chain WHERE 1=1"
        params: List[Any] = []

        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since)
        if until is not None:
            query += " AND timestamp <= ?"
            params.append(until)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["violations"] = json.loads(d["violations_json"])
                results.append(d)
            return results

    def prune_old_entries(self, days: int = 90) -> int:
        """
        Prunes entries older than the retention threshold and reclaims disk space.
        """
        if not self.config.enabled:
            return 0

        cutoff = time.time() - (days * 86400.0)
        with self._write_lock:
            conn = self._get_write_connection()
            conn.execute("BEGIN EXCLUSIVE;")
            try:
                cursor = conn.execute("DELETE FROM audit_chain WHERE timestamp < ?", (cutoff,))
                deleted = cursor.rowcount
                conn.execute("COMMIT;")
                if deleted > 1000:
                    try:
                        conn.execute("VACUUM;")
                    except Exception:
                        pass
                return deleted
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

    def get_stats(self) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"total_events": 0, "blocked_events": 0, "allowed_events": 0, "pending_events": 0}

        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
                    SUM(CASE WHEN verdict IN ('ALLOW', 'REDACTED') THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN verdict = 'REQUIRE_APPROVAL' THEN 1 ELSE 0 END) as pending
                FROM audit_chain
            """)
            row = cursor.fetchone()
            return {
                "total_events": row["total"] or 0,
                "blocked_events": row["blocked"] or 0,
                "allowed_events": row["allowed"] or 0,
                "pending_events": row["pending"] or 0,
            }

    def export_cef(self, entry: Dict[str, Any]) -> str:
        """
        Formats an audit ledger record into Common Event Format (CEF) for SIEMs (Splunk, Datadog, Sentinel).
        """
        severity = 10 if entry.get("verdict") == "BLOCK" else (5 if entry.get("verdict") == "REQUIRE_APPROVAL" else 1)
        violations = entry.get("violations", [])
        msg = violations[0].get("reason", "") if violations else f"MCP Tool Invocation {entry.get('verdict')}"
        entry_id = entry.get("id", 0)
        
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        return (
            f"CEF:0|MCPSecurity|MCPShield|1.0|{entry.get('verdict')}|{entry.get('tool_name')}|{severity}|"
            f"src={entry.get('user_id', 'unknown')} suser={entry.get('session_id', 'unknown')} "
            f"act={entry.get('direction', 'unknown')} cs1={entry.get('entry_hash', '')} cs1Label=EntryHash "
            f"cs2={entry.get('prev_hash', '')} cs2Label=PrevHash cn1={entry_id} cn1Label=EventId msg={msg.replace('|', '_')}"
        )

    def export_syslog(self, entry: Dict[str, Any]) -> str:
        """
        Formats an audit ledger record into RFC 5424 Syslog format.
        """
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(entry.get("timestamp", time.time())))
        cef_msg = self.export_cef(entry)
        return f"<134>1 {ts} fortress-gateway fortress - - - {cef_msg}"

    def export_stix_bundle(self, entries: List[Dict[str, Any]]) -> str:
        """
        Exports audit records into an OASIS STIX 2.0 JSON Bundle for SIEM/SOAR/threat intelligence ingestion.
        """
        import uuid
        bundle_id = f"bundle--{uuid.uuid4()}"
        stix_objects = []

        for entry in entries:
            ts_str = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(entry.get("timestamp", time.time())))
            verdict = entry.get("verdict", "ALLOW")
            tool_name = entry.get("tool_name", "unknown")
            user_id = entry.get("user_id", "unknown")
            session_id = entry.get("session_id", "unknown")
            violations = entry.get("violations", [])

            observed_data = {
                "type": "observed-data",
                "id": f"observed-data--{uuid.uuid4()}",
                "created": ts_str,
                "modified": ts_str,
                "first_observed": ts_str,
                "last_observed": ts_str,
                "number_observed": 1,
                "objects": {
                    "0": {
                        "type": "user-account",
                        "user_id": user_id,
                        "account_login": session_id,
                    },
                    "1": {
                        "type": "network-traffic",
                        "protocol": "mcp-jsonrpc",
                        "extensions": {
                            "x-fortress-event": {
                                "verdict": verdict,
                                "tool_name": tool_name,
                                "direction": entry.get("direction", "INBOUND"),
                                "entry_hash": entry.get("entry_hash", ""),
                                "prev_hash": entry.get("prev_hash", ""),
                                "violations": violations,
                            }
                        }
                    }
                }
            }
            stix_objects.append(observed_data)

            if verdict == "BLOCK":
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": ts_str,
                    "modified": ts_str,
                    "name": f"Fortress Block: {tool_name}",
                    "description": f"MCP Security Gateway blocked call to {tool_name} for session {session_id}",
                    "pattern": f"[network-traffic:extensions.'x-fortress-event'.verdict = 'BLOCK']",
                    "valid_from": ts_str,
                }
                stix_objects.append(indicator)

        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.0",
            "objects": stix_objects,
        }
        return json.dumps(bundle, indent=2)

    def close(self) -> None:
        """Cleanly closes persistent SQLite write connection."""
        with self._write_lock:
            if self._write_conn is not None:
                try:
                    self._write_conn.execute("COMMIT;")
                except Exception:
                    pass
                try:
                    self._write_conn.close()
                except Exception:
                    pass
                self._write_conn = None
