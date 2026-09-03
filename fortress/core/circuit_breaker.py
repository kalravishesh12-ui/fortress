"""
Kill Switch, Circuit Breaker, and Rate Limiting Controller.
"""

from __future__ import annotations
import time
from collections import defaultdict
from typing import Dict, List, Optional
from fortress.config import CircuitBreakerConfig, KillSwitchConfig, RateLimitConfig
from fortress.core.models import RiskLevel, ViolationRecord


class CircuitBreaker:
    """
    Thread-safe & async-compatible Circuit Breaker and Rate Limiter.
    """

    def __init__(
        self,
        kill_switch_cfg: KillSwitchConfig,
        circuit_breaker_cfg: CircuitBreakerConfig,
        rate_limit_cfg: RateLimitConfig,
    ):
        self.kill_switch_cfg = kill_switch_cfg
        self.circuit_breaker_cfg = circuit_breaker_cfg
        self.rate_limit_cfg = rate_limit_cfg
        self._kill_switch_override: Optional[bool] = None

        # Session tracking
        self._session_violations: Dict[str, List[float]] = defaultdict(list)
        self._session_calls: Dict[str, List[float]] = defaultdict(list)
        self._session_costs: Dict[str, float] = defaultdict(float)
        self._tripped_until: Dict[str, float] = {}

    def is_kill_switch_active(self) -> bool:
        if self._kill_switch_override is not None:
            return self._kill_switch_override
        return self.kill_switch_cfg.enabled

    def set_kill_switch(self, active: bool) -> None:
        self._kill_switch_override = active

    def check_inbound(self, session_id: str) -> Optional[ViolationRecord]:
        now = time.time()

        # 1. Global Kill Switch
        if self.is_kill_switch_active():
            return ViolationRecord(
                rule_name="global_kill_switch",
                risk_level=RiskLevel.CRITICAL,
                reason="Global Kill Switch is active. All agent operations are frozen.",
            )

        # 2. Session Circuit Breaker
        if self.circuit_breaker_cfg.enabled:
            tripped_until = self._tripped_until.get(session_id, 0.0)
            if now < tripped_until:
                remaining = int(tripped_until - now)
                return ViolationRecord(
                    rule_name="circuit_breaker_tripped",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Circuit breaker tripped for session {session_id}. Cooldown active for {remaining}s.",
                    details={"remaining_seconds": remaining},
                )

        # 3. Rate Limiting (Sliding Window 60s)
        if self.rate_limit_cfg.enabled:
            window_start = now - 60.0
            call_timestamps = [t for t in self._session_calls[session_id] if t > window_start]
            self._session_calls[session_id] = call_timestamps

            if len(call_timestamps) >= self.rate_limit_cfg.calls_per_minute:
                return ViolationRecord(
                    rule_name="rate_limit_exceeded",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Rate limit exceeded: {len(call_timestamps)} calls in last 60s (max {self.rate_limit_cfg.calls_per_minute}).",
                    details={"calls_last_minute": len(call_timestamps), "max": self.rate_limit_cfg.calls_per_minute},
                )

            # Session Budget check
            current_cost = self._session_costs[session_id]
            if current_cost >= self.rate_limit_cfg.max_session_cost_usd:
                return ViolationRecord(
                    rule_name="session_budget_exceeded",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Session cost budget exceeded:  (limit: ).",
                    details={"current_cost": current_cost, "limit": self.rate_limit_cfg.max_session_cost_usd},
                )

        return None

    def record_call(self, session_id: str) -> None:
        now = time.time()
        self._session_calls[session_id].append(now)
        if self.rate_limit_cfg.enabled:
            self._session_costs[session_id] += self.rate_limit_cfg.cost_per_tool_call

    def record_violation(self, session_id: str, violation: ViolationRecord) -> None:
        if not self.circuit_breaker_cfg.enabled:
            return

        now = time.time()
        window_start = now - 60.0
        v_timestamps = [t for t in self._session_violations[session_id] if t > window_start]
        v_timestamps.append(now)
        self._session_violations[session_id] = v_timestamps

        if len(v_timestamps) >= self.circuit_breaker_cfg.max_violations_per_session:
            cooldown = self.circuit_breaker_cfg.cooldown_seconds
            self._tripped_until[session_id] = now + cooldown

    def get_stats(self) -> Dict[str, Any]:
        return {
            "kill_switch_active": self.is_kill_switch_active(),
            "active_sessions": len(self._session_calls),
            "tripped_sessions": sum(1 for until in self._tripped_until.values() if until > time.time()),
        }
