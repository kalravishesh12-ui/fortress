"""
Schema Pinning & Rug Pull Defense for MCP Tools.
Cryptographically signs tool schemas and intercepts tools/list to stop dynamic poisoning.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from mcp_shield.config import MCPShieldPolicy
from mcp_shield.core.injection_detector import InjectionDetector
from mcp_shield.core.models import JSONRPCResponse, RiskLevel, ViolationRecord


class SchemaPinner:
    """
    Cryptographically pins and signs MCP tool schemas (HMAC-SHA256) upon first connection.
    Detects dynamic tool poisoning, silent description modifications, and schema mutations (Rug Pulls).
    """

    def __init__(self, policy: Optional[MCPShieldPolicy] = None):
        self.policy = policy
        self._secret_key = (
            policy.audit_ledger.hmac_secret_key.encode("utf-8")
            if policy and policy.audit_ledger
            else b"mcp_shield_enterprise_hmac_secret_2026"
        )
        self._pinned_hashes: Dict[str, str] = {}
        self._pinned_signatures: Dict[str, str] = {}
        self._pinned_schemas: Dict[str, Dict[str, Any]] = {}
        self._pinned_timestamps: Dict[str, float] = {}
        outbound_cfg = policy.outbound_guard if policy else None
        self.injection_detector = InjectionDetector(outbound_cfg)

    @property
    def pinned_tools_count(self) -> int:
        return len(self._pinned_hashes)

    def compute_schema_hash(self, tool_def: Dict[str, Any]) -> str:
        """
        Computes deterministic SHA-256 of canonical tool definition.
        """
        canonical_obj = {
            "name": tool_def.get("name", "").strip(),
            "description": tool_def.get("description", "").strip(),
            "inputSchema": tool_def.get("inputSchema", {}),
        }
        serialized = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def sign_schema_hash(self, schema_hash: str) -> str:
        """
        Signs the schema hash with the enterprise HMAC secret key.
        """
        return hmac.new(self._secret_key, schema_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def inspect_tools_list_response(
        self,
        response: JSONRPCResponse,
        allow_auto_pin: bool = True,
    ) -> Tuple[bool, List[ViolationRecord]]:
        """
        Inspects tools/list response for schema mutations and prompt injections.
        Returns (is_valid, violations).
        """
        if not response.result or not isinstance(response.result, dict):
            return True, []

        tools = response.result.get("tools", [])
        if not isinstance(tools, list):
            return True, []

        violations: List[ViolationRecord] = []

        for tool in tools:
            if not isinstance(tool, dict) or "name" not in tool:
                continue

            tool_name = tool["name"]
            tool_desc = tool.get("description", "")
            current_hash = self.compute_schema_hash(tool)

            # 1. Scan tool description for embedded indirect prompt injection
            if tool_desc:
                _, injection_violations = self.injection_detector.inspect(tool_desc)
                if injection_violations:
                    for iv in injection_violations:
                        violations.append(
                            ViolationRecord(
                                rule_name="schema_poisoning_injection_detected",
                                risk_level=RiskLevel.CRITICAL,
                                reason=f"Tool '{tool_name}' description contains prompt injection: {iv.reason}",
                                details={"tool": tool_name, "snippet": tool_desc[:120]},
                            )
                        )

            # 2. Check for schema drift / mutation against pinned hash
            if tool_name in self._pinned_hashes:
                expected_hash = self._pinned_hashes[tool_name]
                expected_sig = self._pinned_signatures.get(tool_name, "")
                recomputed_sig = self.sign_schema_hash(expected_hash)

                if expected_sig != recomputed_sig:
                    violations.append(
                        ViolationRecord(
                            rule_name="schema_tamper_signature_invalid",
                            risk_level=RiskLevel.CRITICAL,
                            reason=f"Cryptographic signature check failed for pinned tool '{tool_name}'.",
                            details={"tool": tool_name},
                        )
                    )

                if current_hash != expected_hash:
                    violations.append(
                        ViolationRecord(
                            rule_name="schema_poisoning_mutation_detected",
                            risk_level=RiskLevel.CRITICAL,
                            reason=f"Tool '{tool_name}' definition has mutated dynamically after initial pinning (Rug Pull detected).",
                            details={
                                "tool": tool_name,
                                "expected_hash": expected_hash,
                                "current_hash": current_hash,
                                "old_desc": self._pinned_schemas.get(tool_name, {}).get("description", ""),
                                "new_desc": tool_desc,
                            },
                        )
                    )
            elif allow_auto_pin:
                self.pin_tool(tool)

        is_valid = len(violations) == 0
        return is_valid, violations

    def pin_tool(self, tool_def: Dict[str, Any]) -> str:
        """
        Cryptographically pins and signs a tool definition.
        """
        name = tool_def["name"]
        h = self.compute_schema_hash(tool_def)
        sig = self.sign_schema_hash(h)
        self._pinned_hashes[name] = h
        self._pinned_signatures[name] = sig
        self._pinned_schemas[name] = tool_def
        self._pinned_timestamps[name] = time.time()
        return h

    def verify_tool_call_pin(self, tool_name: str) -> Optional[ViolationRecord]:
        """
        Verifies that an incoming tool call matches an established, signed schema pin.
        """
        if not self.policy or not self.policy.schema_pinning.enabled:
            return None

        if self.pinned_tools_count > 0 and tool_name not in self._pinned_hashes:
            return ViolationRecord(
                rule_name="unregistered_tool_call",
                risk_level=RiskLevel.HIGH,
                reason=f"Tool '{tool_name}' was not declared or pinned during initial tools/list handshake.",
                details={"tool": tool_name},
            )
        return None

    def get_pins_summary(self) -> List[Dict[str, Any]]:
        return [
            {
                "tool": name,
                "hash": self._pinned_hashes[name],
                "signature": self._pinned_signatures[name][:16] + "...",
                "pinned_at": self._pinned_timestamps.get(name, 0.0),
            }
            for name in self._pinned_hashes
        ]

    def clear_pins(self) -> None:
        self._pinned_hashes.clear()
        self._pinned_signatures.clear()
        self._pinned_schemas.clear()
        self._pinned_timestamps.clear()
