"""
Unified Dual-Stage Security Interception Engine.
"""

from __future__ import annotations
import fnmatch
import time
from typing import Any, Optional
from fortress.config import MCPShieldPolicy
from fortress.core.circuit_breaker import CircuitBreaker
from fortress.core.hitl import HITLManager
from fortress.core.injection_detector import InjectionDetector
from fortress.core.models import (
    InspectionResult,
    JSONRPCRequest,
    JSONRPCResponse,
    RiskLevel,
    SecurityContext,
    SecurityVerdict,
    ViolationRecord,
)
from fortress.core.path_guard import PathGuard
from fortress.core.pii_redactor import PIIRedactor
from fortress.core.rbac import RBACValidator
from fortress.core.secret_scanner import SecretScanner
from fortress.core.ssrf_guard import SSRFGuard
from fortress.core.schema_pinner import SchemaPinner
from fortress.audit.ledger import AuditLedger


from collections import OrderedDict

class TaintStore(OrderedDict):
    """
    LRU bounded dictionary with TTL expiration for stateful session taint tracking.
    Guarantees O(1) lookups and bounded memory under long-running production workloads.
    """
    def __init__(self, max_size: int = 10000, ttl_seconds: float = 3600.0, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._timestamps: dict[str, float] = {}

    def __getitem__(self, key: str) -> list[str]:
        val = super().__getitem__(key)
        now = time.time()
        if now - self._timestamps.get(key, 0.0) > self.ttl_seconds:
            self.__delitem__(key)
            raise KeyError(key)
        self.move_to_end(key)
        return val

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            now = time.time()
            if now - self._timestamps.get(str(key), 0.0) <= self.ttl_seconds:
                return True
            self.__delitem__(str(key))
        return False

    def __setitem__(self, key: str, value: list[str]):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        self._timestamps[key] = time.time()
        if len(self) > self.max_size:
            oldest_key, _ = self.popitem(last=False)
            self._timestamps.pop(oldest_key, None)

    def __delitem__(self, key: str):
        super().__delitem__(key)
        self._timestamps.pop(key, None)

    def items(self):
        now = time.time()
        expired = [k for k, ts in self._timestamps.items() if now - ts > self.ttl_seconds]
        for k in expired:
            try:
                del self[k]
            except KeyError:
                pass
        return super().items()


class SecurityEngine:
    """
    Deterministic Inbound & Outbound Interception Engine.
    """

    def __init__(self, policy: Optional[MCPShieldPolicy] = None):
        self.policy = policy or MCPShieldPolicy()
        self.circuit_breaker = CircuitBreaker(
            kill_switch_cfg=self.policy.kill_switch,
            circuit_breaker_cfg=self.policy.circuit_breaker,
            rate_limit_cfg=self.policy.rate_limiting,
        )
        self.rbac = RBACValidator(self.policy.rbac)
        self.path_guard = PathGuard(self.policy.path_guard)
        self.ssrf_guard = SSRFGuard(self.policy.ssrf_guard)
        self.hitl = HITLManager(self.policy.hitl)
        self.secret_scanner = SecretScanner(self.policy.outbound_guard)
        self.pii_redactor = PIIRedactor(self.policy.outbound_guard)
        self.injection_detector = InjectionDetector(self.policy.outbound_guard)
        self.audit_ledger = AuditLedger(self.policy.audit_ledger)
        self.schema_pinner = SchemaPinner(self.policy)
        self._tainted_sessions = TaintStore(max_size=10000, ttl_seconds=3600.0)

    def inspect_inbound(
        self,
        request: JSONRPCRequest,
        context: SecurityContext,
        auth_token: Optional[str] = None
    ) -> InspectionResult:
        start_time = time.perf_counter()
        violations: list[ViolationRecord] = []

        if not request.is_tool_call:
            if self.circuit_breaker.is_kill_switch_active():
                v = ViolationRecord(
                    rule_name="global_kill_switch",
                    risk_level=RiskLevel.CRITICAL,
                    reason="Global Kill Switch is active. All agent operations are frozen.",
                )
                self.audit_ledger.log_event(
                    session_id=context.session_id,
                    user_id=context.user_id,
                    tool_name=request.method,
                    direction="INBOUND",
                    verdict=SecurityVerdict.BLOCK,
                    violations=[v],
                    payload=request.model_dump(),
                )
                return InspectionResult(
                    verdict=SecurityVerdict.BLOCK,
                    violations=[v],
                    latency_ms=(time.perf_counter() - start_time) * 1000,
                    blocked_reason=v.reason,
                )
            return InspectionResult(
                verdict=SecurityVerdict.ALLOW,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        tool_name = request.tool_name or "unknown_tool"
        args = request.tool_arguments

        # 1. Kill Switch & Circuit Breaker / Rate Limit Check
        cb_violation = self.circuit_breaker.check_inbound(context.session_id)
        if cb_violation:
            violations.append(cb_violation)
            return self._finalize_inbound_decision(
                request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, cb_violation.reason
            )

        # 2. RBAC & Identity Check
        context = self.rbac.resolve_identity(context, auth_token)
        rbac_allowed, rbac_requires_hitl, rbac_violation = self.rbac.check_tool_access(tool_name, context.role)
        if not rbac_allowed and rbac_violation:
            violations.append(rbac_violation)
            self.circuit_breaker.record_violation(context.session_id, rbac_violation)
            return self._finalize_inbound_decision(
                request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, rbac_violation.reason
            )

        # 3. Global Tool Policy Deny/Allow Check
        for deny_pat in self.policy.tool_policies.deny_patterns:
            if fnmatch.fnmatch(tool_name.lower(), deny_pat.lower()):
                v = ViolationRecord(
                    rule_name="tool_policy_denied",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Tool '{tool_name}' matches global deny list rule '{deny_pat}'.",
                    details={"tool": tool_name, "rule": deny_pat},
                )
                violations.append(v)
                self.circuit_breaker.record_violation(context.session_id, v)
                return self._finalize_inbound_decision(
                    request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, v.reason
                )

        # 3.5. Stateful Taint-Tracking Check (Compound Tool Chaining Protection)
        if self.policy.taint_tracking.enabled:
            session_taints = self._tainted_sessions.get(context.session_id, [])
            is_egress_tool = any(fnmatch.fnmatch(tool_name.lower(), pat.lower()) for pat in self.policy.taint_tracking.egress_patterns)
            
            if session_taints and is_egress_tool:
                context.is_tainted = True
                context.taint_sources = list(session_taints)
                taint_violation = ViolationRecord(
                    rule_name="compound_taint_egress_violation",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Session is tainted by sensitive data ingested from {session_taints}; outbound egress tool '{tool_name}' requires human authorization.",
                    details={"tool": tool_name, "taint_sources": session_taints},
                )
                violations.append(taint_violation)
                if self.policy.taint_tracking.action_on_taint == "block":
                    return self._finalize_inbound_decision(
                        request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, taint_violation.reason
                    )
                else:
                    pending = self.hitl.create_approval_request(request, context, taint_violation.reason)
                    return self._finalize_inbound_decision(
                        request, context, tool_name, SecurityVerdict.REQUIRE_APPROVAL, violations, start_time, pending_token=pending.token
                    )

        # 4. Argument & Path Traversal Guard
        path_violations = self.path_guard.inspect_arguments(args)
        if path_violations:
            violations.extend(path_violations)
            for v in path_violations:
                self.circuit_breaker.record_violation(context.session_id, v)
            return self._finalize_inbound_decision(
                request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, path_violations[0].reason
            )

        # 5. Egress & SSRF Guard
        ssrf_violations = self.ssrf_guard.inspect_arguments(args)
        if ssrf_violations:
            violations.extend(ssrf_violations)
            for v in ssrf_violations:
                self.circuit_breaker.record_violation(context.session_id, v)
            return self._finalize_inbound_decision(
                request, context, tool_name, SecurityVerdict.BLOCK, violations, start_time, ssrf_violations[0].reason
            )

        # 6. Human-in-the-Loop Check
        needs_approval = rbac_requires_hitl
        if not needs_approval:
            for approval_pat in self.policy.tool_policies.require_approval:
                if fnmatch.fnmatch(tool_name.lower(), approval_pat.lower()):
                    needs_approval = True
                    break

        if needs_approval:
            reason = f"Tool '{tool_name}' is classified as high-risk and requires human verification."
            pending = self.hitl.create_approval_request(request, context, reason)
            return self._finalize_inbound_decision(
                request,
                context,
                tool_name,
                SecurityVerdict.REQUIRE_APPROVAL,
                violations,
                start_time,
                pending_token=pending.token,
            )

        # All inbound checks passed
        self.circuit_breaker.record_call(context.session_id)
        return self._finalize_inbound_decision(
            request, context, tool_name, SecurityVerdict.ALLOW, violations, start_time
        )

    def _finalize_inbound_decision(
        self,
        request: JSONRPCRequest,
        context: SecurityContext,
        tool_name: str,
        verdict: SecurityVerdict,
        violations: list[ViolationRecord],
        start_time: float,
        blocked_reason: Optional[str] = None,
        pending_token: Optional[str] = None,
    ) -> InspectionResult:
        latency = (time.perf_counter() - start_time) * 1000
        self.audit_ledger.log_event(
            session_id=context.session_id,
            user_id=context.user_id,
            tool_name=tool_name,
            direction="INBOUND",
            verdict=verdict,
            violations=violations,
            payload=request.model_dump(),
        )
        return InspectionResult(
            verdict=verdict,
            violations=violations,
            latency_ms=latency,
            blocked_reason=blocked_reason,
            pending_token=pending_token,
        )

    def _sanitize_string_leaf(self, s: str, violations: list[ViolationRecord]) -> str:
        if self.policy.outbound_guard.scan_secrets:
            s = self.secret_scanner._scan_text(s, violations)
        if self.policy.outbound_guard.mask_pii:
            s = self.pii_redactor._mask_text(s, violations)
        if self.policy.outbound_guard.scan_prompt_injection:
            s = self.injection_detector._scan_text(s, violations)
        return s

    def _sanitize_payload_single_pass(self, data: Any, violations: list[ViolationRecord], depth: int = 0) -> Any:
        if depth > 20:
            return data
        if isinstance(data, str):
            return self._sanitize_string_leaf(data, violations)
        elif isinstance(data, dict):
            return {k: self._sanitize_payload_single_pass(v, violations, depth + 1) for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return [self._sanitize_payload_single_pass(item, violations, depth + 1) for item in data]
        return data

    def inspect_outbound(
        self,
        response: JSONRPCResponse,
        request: Optional[JSONRPCRequest],
        context: SecurityContext,
    ) -> InspectionResult:
        start_time = time.perf_counter()
        tool_name = request.tool_name if (request and request.is_tool_call) else "response"
        violations: list[ViolationRecord] = []

        if response.is_error or response.result is None:
            latency = (time.perf_counter() - start_time) * 1000
            return InspectionResult(verdict=SecurityVerdict.ALLOW, latency_ms=latency)

        current_data = response.result
        verdict = SecurityVerdict.ALLOW

        # Record taint if tool matches sensitive read
        if self.policy.taint_tracking.enabled and tool_name:
            is_sensitive_read = any(fnmatch.fnmatch(tool_name.lower(), pat.lower()) for pat in self.policy.taint_tracking.sensitive_read_patterns)
            if is_sensitive_read:
                if context.session_id not in self._tainted_sessions:
                    self._tainted_sessions[context.session_id] = []
                if tool_name not in self._tainted_sessions[context.session_id]:
                    self._tainted_sessions[context.session_id].append(tool_name)
                context.is_tainted = True
                context.taint_sources = list(self._tainted_sessions[context.session_id])

        # Single-Pass Unified Outbound Sanitization (Secrets + PII + Injections)
        current_data = self._sanitize_payload_single_pass(current_data, violations)

        if violations:
            has_blocked_injection = any(
                v.rule_name.startswith("prompt_injection_") and v.risk_level == RiskLevel.CRITICAL
                for v in violations
            )
            if has_blocked_injection and self.policy.outbound_guard.injection_action == "block":
                verdict = SecurityVerdict.BLOCK
                current_data = {
                    "error": "Blocked by Fortress: Response contained dangerous indirect prompt injection."
                }
            else:
                verdict = SecurityVerdict.REDACTED

        modified_response = response.model_copy(deep=True)
        modified_response.result = current_data

        latency = (time.perf_counter() - start_time) * 1000
        self.audit_ledger.log_event(
            session_id=context.session_id,
            user_id=context.user_id,
            tool_name=tool_name,
            direction="OUTBOUND",
            verdict=verdict,
            violations=violations,
            payload=modified_response.model_dump(),
        )

        return InspectionResult(
            verdict=verdict,
            modified_payload=modified_response.model_dump(),
            violations=violations,
            latency_ms=latency,
        )
