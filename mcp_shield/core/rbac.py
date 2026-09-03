"""
Role-Based Access Control (RBAC) & Identity Verification for MCP Tools.
"""

from __future__ import annotations
import fnmatch
from typing import Optional, Tuple
from mcp_shield.config import RBACConfig
from mcp_shield.core.models import RiskLevel, SecurityContext, ViolationRecord


class RBACValidator:
    """
    Deterministic RBAC & Identity Enforcement.
    """

    def __init__(self, config: RBACConfig):
        self.config = config

    def resolve_identity(self, context: SecurityContext, auth_token: Optional[str] = None) -> SecurityContext:
        """
        Resolves the user role based on provided token or user_id.
        """
        if not self.config.enabled:
            return context

        role = self.config.default_role

        if auth_token and auth_token in self.config.api_tokens:
            role = self.config.api_tokens[auth_token]
        elif context.user_id in self.config.user_roles:
            role = self.config.user_roles[context.user_id]
        elif context.role in self.config.roles:
            role = context.role

        context.role = role
        return context

    def check_tool_access(self, tool_name: str, role_name: str) -> Tuple[bool, bool, Optional[ViolationRecord]]:
        """
        Checks whether role has permission to call tool.
        Returns (is_allowed, requires_approval, violation_if_any).
        """
        if not self.config.enabled:
            return True, False, None

        role_cfg = self.config.roles.get(role_name)
        if not role_cfg:
            return False, False, ViolationRecord(
                rule_name="rbac_unknown_role",
                risk_level=RiskLevel.HIGH,
                reason=f"Role '{role_name}' is not defined in RBAC policy.",
                details={"role": role_name, "tool": tool_name},
            )

        # Check explicit deny patterns first (Fail-Closed)
        for deny_pat in role_cfg.denied_tools:
            if fnmatch.fnmatch(tool_name.lower(), deny_pat.lower()):
                return False, False, ViolationRecord(
                    rule_name="rbac_tool_denied",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Tool '{tool_name}' is explicitly forbidden for role '{role_name}' (rule: '{deny_pat}').",
                    details={"role": role_name, "tool": tool_name, "matched_pattern": deny_pat},
                )

        # Check allow patterns
        is_allowed = False
        for allow_pat in role_cfg.allowed_tools:
            if fnmatch.fnmatch(tool_name.lower(), allow_pat.lower()):
                is_allowed = True
                break

        if not is_allowed:
            return False, False, ViolationRecord(
                rule_name="rbac_tool_not_permitted",
                risk_level=RiskLevel.HIGH,
                reason=f"Tool '{tool_name}' is not allowed for role '{role_name}'.",
                details={"role": role_name, "tool": tool_name},
            )

        # Check if requires human approval
        requires_approval = False
        for approval_pat in role_cfg.require_approval:
            if fnmatch.fnmatch(tool_name.lower(), approval_pat.lower()):
                requires_approval = True
                break

        return True, requires_approval, None
