"""
Declarative Policy Configuration & Validation for MCP-Shield.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import yaml


class KillSwitchConfig(BaseModel):
    enabled: bool = False


class CircuitBreakerConfig(BaseModel):
    enabled: bool = True
    max_violations_per_session: int = 5
    cooldown_seconds: int = 60


class RateLimitConfig(BaseModel):
    enabled: bool = True
    calls_per_minute: int = 60
    burst_size: int = 15
    max_session_cost_usd: float = 10.0
    cost_per_tool_call: float = 0.002


class RBACRole(BaseModel):
    allowed_tools: List[str] = Field(default_factory=lambda: ["*"])
    denied_tools: List[str] = Field(default_factory=list)
    require_approval: List[str] = Field(default_factory=list)


class RBACConfig(BaseModel):
    enabled: bool = True
    default_role: str = "agent"
    roles: Dict[str, RBACRole] = Field(default_factory=lambda: {
        "admin": RBACRole(allowed_tools=["*"], denied_tools=[], require_approval=[]),
        "developer": RBACRole(
            allowed_tools=["read_*", "get_*", "list_*", "search_*", "fetch_*", "query_*", "write_*", "create_*", "execute_*"],
            denied_tools=["*shell_exec*", "*eval*", "*system_cmd*", "delete_database", "drop_*"],
            require_approval=["write_*", "create_*", "execute_*"]
        ),
        "readonly": RBACRole(
            allowed_tools=["read_*", "get_*", "list_*", "search_*", "fetch_*"],
            denied_tools=["write_*", "create_*", "delete_*", "update_*", "drop_*", "*exec*"],
            require_approval=[]
        ),
        "agent": RBACRole(
            allowed_tools=["read_*", "get_*", "list_*", "search_*", "fetch_*", "execute_task"],
            denied_tools=["*exec*", "*eval*", "*system*", "delete_*", "drop_*", "transfer_funds"],
            require_approval=["execute_task"]
        )
    })
    user_roles: Dict[str, str] = Field(default_factory=lambda: {
        "admin_user": "admin",
        "dev_agent": "developer",
        "readonly_bot": "readonly"
    })
    api_tokens: Dict[str, str] = Field(default_factory=lambda: {
        "mcp_sec_admin_token_99x": "admin",
        "mcp_sec_dev_token_42a": "developer",
        "mcp_sec_agent_token_07z": "agent"
    })


class TaintTrackingConfig(BaseModel):
    enabled: bool = True
    sensitive_read_patterns: List[str] = Field(default_factory=lambda: [
        "read_*", "get_*", "query_*", "fetch_*", "search_*", "cat_*", "download_*"
    ])
    egress_patterns: List[str] = Field(default_factory=lambda: [
        "send_*", "post_*", "upload_*", "email_*", "webhook_*", "transfer_*", "export_*"
    ])
    action_on_taint: str = "require_approval"  # "require_approval" or "block"


class SchemaPinningConfig(BaseModel):
    enabled: bool = True
    auto_pin_on_first_seen: bool = True
    block_on_mutation: bool = True


class ToolPoliciesConfig(BaseModel):
    allow_patterns: List[str] = Field(default_factory=lambda: [
        "read_*", "get_*", "list_*", "search_*", "fetch_*", "query_*", "browse_*"
    ])
    deny_patterns: List[str] = Field(default_factory=lambda: [
        "*shell_exec*", "*eval*", "*system_cmd*", "*raw_exec*", "delete_database", "drop_*", "destroy_*", "rm_*"
    ])
    require_approval: List[str] = Field(default_factory=lambda: [
        "execute_query", "update_*", "delete_*", "write_*", "send_email", "transfer_*", "deploy_*"
    ])


class PathGuardConfig(BaseModel):
    enabled: bool = True
    allowed_base_directories: List[str] = Field(default_factory=lambda: ["."])
    blocked_paths: List[str] = Field(default_factory=lambda: [
        ".ssh", "id_rsa", "id_ed25519", "id_dsa",
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "C:\\Windows\\System32\\config", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ".aws/credentials", ".env", ".git/config", "authorized_keys"
    ])
    block_traversal_patterns: List[str] = Field(default_factory=lambda: [
        "..", "%2e%2e", "%252e%252e", "..\\", "../", "%00"
    ])


class SSRFGuardConfig(BaseModel):
    enabled: bool = True
    blocked_ip_ranges: List[str] = Field(default_factory=lambda: [
        "169.254.169.254/32",  # AWS / GCP / Azure IMDS
        "169.254.0.0/16",      # Link-local
        "127.0.0.0/8",         # Loopback IPv4
        "10.0.0.0/8",          # Private Class A
        "172.16.0.0/12",       # Private Class B
        "192.168.0.0/16",      # Private Class C
        "0.0.0.0/8",           # Zero network
        "::1/128",             # IPv6 Loopback
        "fc00::/7",            # IPv6 Unique Local
        "fe80::/10"            # IPv6 Link-Local
    ])
    blocked_domains: List[str] = Field(default_factory=lambda: [
        "metadata.google.internal",
        "instance-data",
        "metadata.azure.com",
        "169.254.169.254.nip.io",
        "localhost",
        "127.0.0.1.nip.io"
    ])
    allowed_domains: List[str] = Field(default_factory=list)


class OutboundGuardConfig(BaseModel):
    scan_secrets: bool = True
    entropy_threshold: float = 4.5
    min_entropy_length: int = 20
    mask_pii: bool = True
    pii_types: List[str] = Field(default_factory=lambda: ["ssn", "credit_card", "email", "phone"])
    scan_prompt_injection: bool = True
    injection_action: str = "sanitize"  # "sanitize" or "block"
    max_response_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit


class AuditLedgerConfig(BaseModel):
    enabled: bool = True
    db_path: str = "./mcp-shield-audit.db"
    hmac_secret_key: str = "mcp_shield_deterministic_enterprise_hmac_secret_2026"
    log_to_console: bool = False


class HITLConfig(BaseModel):
    mode: str = "terminal"  # "terminal", "dashboard", "webhook"
    webhook_url: Optional[str] = None
    timeout_seconds: int = 60


class MCPShieldPolicy(BaseModel):
    version: str = "1.0"
    kill_switch: KillSwitchConfig = Field(default_factory=KillSwitchConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    rate_limiting: RateLimitConfig = Field(default_factory=RateLimitConfig)
    rbac: RBACConfig = Field(default_factory=RBACConfig)
    tool_policies: ToolPoliciesConfig = Field(default_factory=ToolPoliciesConfig)
    taint_tracking: TaintTrackingConfig = Field(default_factory=TaintTrackingConfig)
    schema_pinning: SchemaPinningConfig = Field(default_factory=SchemaPinningConfig)
    path_guard: PathGuardConfig = Field(default_factory=PathGuardConfig)
    ssrf_guard: SSRFGuardConfig = Field(default_factory=SSRFGuardConfig)
    outbound_guard: OutboundGuardConfig = Field(default_factory=OutboundGuardConfig)
    audit_ledger: AuditLedgerConfig = Field(default_factory=AuditLedgerConfig)
    hitl: HITLConfig = Field(default_factory=HITLConfig)


def load_policy(path: Optional[str] = None) -> MCPShieldPolicy:
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return MCPShieldPolicy.model_validate(data)
    
    # Fallback to local mcp-policy.yaml if present
    default_file = "mcp-policy.yaml"
    if os.path.exists(default_file):
        with open(default_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return MCPShieldPolicy.model_validate(data)

    return MCPShieldPolicy()


def save_policy(policy: MCPShieldPolicy, path: str = "mcp-policy.yaml") -> None:
    data = policy.model_dump()
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
