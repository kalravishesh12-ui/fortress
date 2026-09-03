"""
Human-in-the-Loop (HITL) Hook & Approval Manager.
"""

from __future__ import annotations
import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from mcp_shield.config import HITLConfig
from mcp_shield.core.models import JSONRPCRequest, SecurityContext
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class PendingApproval:
    token: str
    tool_name: str
    arguments: dict
    context: SecurityContext
    reason: str
    created_at: float = field(default_factory=time.time)
    status: ApprovalStatus = ApprovalStatus.PENDING
    approver: Optional[str] = None
    decision_reason: Optional[str] = None
    event: asyncio.Event = field(default_factory=asyncio.Event)


class HITLManager:
    """
    Coordinates Human-in-the-Loop approval requests across Terminal, Webhooks, and Web UI.
    """

    def __init__(self, config: HITLConfig):
        self.config = config
        self._pending_approvals: Dict[str, PendingApproval] = {}
        self.console = Console()

    def create_approval_request(
        self,
        request: JSONRPCRequest,
        context: SecurityContext,
        reason: str
    ) -> PendingApproval:
        token = f"hitl_tok_{uuid.uuid4().hex[:16]}"
        pending = PendingApproval(
            token=token,
            tool_name=request.tool_name or "unknown",
            arguments=request.tool_arguments,
            context=context,
            reason=reason,
        )
        self._pending_approvals[token] = pending
        return pending

    def approve(self, token: str, approver: str = "human_operator") -> bool:
        pending = self._pending_approvals.get(token)
        if pending and pending.status == ApprovalStatus.PENDING:
            pending.status = ApprovalStatus.APPROVED
            pending.approver = approver
            pending.event.set()
            return True
        return False

    def reject(self, token: str, rejecter: str = "human_operator", reason: str = "Manually rejected") -> bool:
        pending = self._pending_approvals.get(token)
        if pending and pending.status == ApprovalStatus.PENDING:
            pending.status = ApprovalStatus.REJECTED
            pending.approver = rejecter
            pending.decision_reason = reason
            pending.event.set()
            return True
        return False

    async def wait_for_decision(self, pending: PendingApproval, timeout: Optional[int] = None) -> ApprovalStatus:
        timeout_sec = timeout if timeout is not None else self.config.timeout_seconds
        
        # If terminal mode, prompt interactively
        if self.config.mode == "terminal":
            self._prompt_terminal(pending)

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=timeout_sec)
            return pending.status
        except asyncio.TimeoutError:
            pending.status = ApprovalStatus.EXPIRED
            pending.decision_reason = f"Approval request timed out after {timeout_sec}s."
            return ApprovalStatus.EXPIRED

    def _prompt_terminal(self, pending: PendingApproval) -> None:
        text = f"[bold yellow]Tool:[/bold yellow] [cyan]{pending.tool_name}[/cyan]\n"
        text += f"[bold yellow]Session ID:[/bold yellow] {pending.context.session_id}\n"
        text += f"[bold yellow]User / Role:[/bold yellow] {pending.context.user_id} ({pending.context.role})\n"
        text += f"[bold yellow]Reason:[/bold yellow] {pending.reason}\n"
        text += f"[bold yellow]Arguments:[/bold yellow] {pending.arguments}"
        
        self.console.print(Panel(text, title="[bold red]?? SENSITIVE TOOL CALL - APPROVAL REQUIRED[/bold red]", border_style="red"))
        
        # Non-blocking terminal prompt
        def do_prompt():
            try:
                approved = Confirm.ask(f"Approve execution of tool '{pending.tool_name}'?", default=False)
                if approved:
                    self.approve(pending.token, approver="terminal_user")
                else:
                    self.reject(pending.token, rejecter="terminal_user", reason="Rejected via terminal")
            except Exception:
                self.reject(pending.token, rejecter="terminal_user", reason="Terminal prompt interrupted")

        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, do_prompt)

    def list_pending(self) -> List[Dict[str, Any]]:
        return [
            {
                "token": p.token,
                "tool_name": p.tool_name,
                "arguments": p.arguments,
                "user_id": p.context.user_id,
                "role": p.context.role,
                "reason": p.reason,
                "created_at": p.created_at,
                "status": p.status.value,
            }
            for p in self._pending_approvals.values()
            if p.status == ApprovalStatus.PENDING
        ]
