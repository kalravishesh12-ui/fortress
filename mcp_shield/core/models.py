"""
Data models for JSON-RPC 2.0 messages, Security Verdicts, and Inspection Context.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
import time
import uuid


class SecurityVerdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACTED = "REDACTED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ViolationRecord(BaseModel):
    rule_name: str
    risk_level: RiskLevel
    reason: str
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityContext(BaseModel):
    session_id: str = Field(default_factory=lambda: f"sess_{uuid.uuid4().hex[:12]}")
    user_id: str = "anonymous"
    role: str = "agent"
    client_name: str = "unknown-client"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)
    is_tainted: bool = False
    taint_sources: List[str] = Field(default_factory=list)


class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    method: str
    params: Optional[Dict[str, Any]] = None

    @property
    def is_tool_call(self) -> bool:
        return self.method in ("tools/call", "call_tool")

    @property
    def tool_name(self) -> Optional[str]:
        if self.is_tool_call and self.params:
            return self.params.get("name")
        return None

    @property
    def tool_arguments(self) -> Dict[str, Any]:
        if self.is_tool_call and self.params:
            args = self.params.get("arguments", {})
            return args if isinstance(args, dict) else {}
        return {}


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = None
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


class InspectionResult(BaseModel):
    verdict: SecurityVerdict
    modified_payload: Optional[Dict[str, Any]] = None
    violations: List[ViolationRecord] = Field(default_factory=list)
    latency_ms: float = 0.0
    pending_token: Optional[str] = None
    blocked_reason: Optional[str] = None

    @property
    def is_blocked(self) -> bool:
        return self.verdict == SecurityVerdict.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.verdict in (SecurityVerdict.ALLOW, SecurityVerdict.REDACTED)

    @property
    def requires_approval(self) -> bool:
        return self.verdict == SecurityVerdict.REQUIRE_APPROVAL
