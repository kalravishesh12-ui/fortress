"""
Kill Switch, Circuit Breaker, and Rate Limiting Controller.
"""

from __future__ import annotations
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional
from fortress.config import CircuitBreakerConfig, GlobalRateLimitConfig, KillSwitchConfig, RateLimitConfig
from fortress.core.models import RiskLevel, ViolationRecord


class TokenBucket:
    """
    Thread-safe Token Bucket for global rate limiting and burst handling.
    """
    def __init__(self, capacity: int, fill_rate: float):
        self.capacity = float(capacity)
        self.fill_rate = float(fill_rate)
        self.tokens = float(capacity)
        self.last_update = time.time()
        self._lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self._lock:
            now = time.time()
            delta = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


class CircuitBreaker:
    """
    Thread-safe & async-compatible Circuit Breaker, Rate Limiter, and Threat Backoff Controller.
    """

    def __init__(
        self,
        kill_switch_cfg: KillSwitchConfig,
        circuit_breaker_cfg: CircuitBreakerConfig,
        rate_limit_cfg: RateLimitConfig,
        global_rate_limit_cfg: Optional[GlobalRateLimitConfig] = None,
    ):
        self.kill_switch_cfg = kill_switch_cfg
        self.circuit_breaker_cfg = circuit_breaker_cfg
        self.rate_limit_cfg = rate_limit_cfg
        self.global_rate_limit_cfg = global_rate_limit_cfg or GlobalRateLimitConfig()
        self._kill_switch_override: Optional[bool] = None

        # Global rate limit token bucket
        burst = self.global_rate_limit_cfg.global_burst_allowance
        rps = self.global_rate_limit_cfg.global_requests_per_second
        self.global_token_bucket = TokenBucket(capacity=burst, fill_rate=rps)

        # Session tracking with O(1) deques
        self._session_violations: Dict[str, deque[float]] = defaultdict(deque)
        self._session_calls: Dict[str, deque[float]] = defaultdict(deque)
        self._session_costs: Dict[str, float] = defaultdict(float)
        self._tripped_until: Dict[str, float] = {}
        self._session_violation_counts: Dict[str, int] = defaultdict(int)
        self._session_backoff_until: Dict[str, float] = {}

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

        # 1.5 Global Rate Limiting
        if self.global_rate_limit_cfg.enabled and not self.global_token_bucket.consume(1.0):
            return ViolationRecord(
                rule_name="global_rate_limit_exceeded",
                risk_level=RiskLevel.HIGH,
                reason="Global gateway rate limit exceeded. Burst allowance exhausted.",
                details={"global_rps": self.global_rate_limit_cfg.global_requests_per_second},
            )

        # 1.8 Threat-Adaptive Exponential Backoff
        if session_id in self._session_backoff_until:
            backoff_until = self._session_backoff_until[session_id]
            if now < backoff_until:
                remaining = backoff_until - now
                return ViolationRecord(
                    rule_name="threat_backoff_active",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Session {session_id} is in threat backoff for repeated violations ({remaining:.1f}s remaining).",
                    details={"remaining_seconds": round(remaining, 1)},
                )
            else:
                del self._session_backoff_until[session_id]

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
            elif session_id in self._tripped_until:
                del self._tripped_until[session_id]

        # 3. Rate Limiting (Sliding Window 60s with O(1) deque eviction)
        if self.rate_limit_cfg.enabled:
            window_start = now - 60.0
            call_q = self._session_calls[session_id]
            while call_q and call_q[0] <= window_start:
                call_q.popleft()

            if len(call_q) >= self.rate_limit_cfg.calls_per_minute:
                return ViolationRecord(
                    rule_name="rate_limit_exceeded",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Rate limit exceeded: {len(call_q)} calls in last 60s (max {self.rate_limit_cfg.calls_per_minute}).",
                    details={"calls_last_minute": len(call_q), "max": self.rate_limit_cfg.calls_per_minute},
                )

            # Session Budget check
            current_cost = self._session_costs[session_id]
            if current_cost >= self.rate_limit_cfg.max_session_cost_usd:
                return ViolationRecord(
                    rule_name="session_budget_exceeded",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Session cost budget exceeded: ${current_cost:.2f} (limit: ${self.rate_limit_cfg.max_session_cost_usd:.2f}).",
                    details={"current_cost": current_cost, "limit": self.rate_limit_cfg.max_session_cost_usd},
                )

        return None

    def record_call(self, session_id: str) -> None:
        now = time.time()
        self._session_calls[session_id].append(now)
        if self.rate_limit_cfg.enabled:
            self._session_costs[session_id] += self.rate_limit_cfg.cost_per_tool_call

    def record_violation(self, session_id: str, violation: ViolationRecord) -> None:
        now = time.time()

        # Track total repeated violations for threat-adaptive backoff
        self._session_violation_counts[session_id] += 1
        count = self._session_violation_counts[session_id]
        if count >= self.circuit_breaker_cfg.max_violations_per_session:
            base = self.global_rate_limit_cfg.threat_backoff_base if self.global_rate_limit_cfg else 2.0
            max_backoff = self.global_rate_limit_cfg.max_threat_backoff_seconds if self.global_rate_limit_cfg else 300.0
            backoff_sec = min(max_backoff, (base ** (count - self.circuit_breaker_cfg.max_violations_per_session + 1)))
            self._session_backoff_until[session_id] = now + backoff_sec

        if not self.circuit_breaker_cfg.enabled:
            return

        window_start = now - 60.0
        v_q = self._session_violations[session_id]
        while v_q and v_q[0] <= window_start:
            v_q.popleft()
        v_q.append(now)

        if len(v_q) >= self.circuit_breaker_cfg.max_violations_per_session:
            cooldown = self.circuit_breaker_cfg.cooldown_seconds
            self._tripped_until[session_id] = now + cooldown

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        # Active prune of expired cooldowns
        expired = [s for s, until in self._tripped_until.items() if until <= now]
        for s in expired:
            del self._tripped_until[s]

        # Active prune of expired backoffs
        expired_backoffs = [s for s, until in self._session_backoff_until.items() if until <= now]
        for s in expired_backoffs:
            del self._session_backoff_until[s]

        return {
            "kill_switch_active": self.is_kill_switch_active(),
            "active_sessions": len(self._session_calls),
            "tripped_sessions": len(self._tripped_until),
            "threat_backoff_sessions": len(self._session_backoff_until),
        }
