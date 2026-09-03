"""
Transparent stdio Reverse-Proxy for Local MCP Servers (Claude Desktop / Cursor).
"""

from __future__ import annotations
import asyncio
import json
import sys
from typing import List, Optional
from fortress.config import MCPShieldPolicy
from fortress.core.engine import SecurityEngine
from fortress.core.hitl import ApprovalStatus
from fortress.core.models import (
    JSONRPCRequest,
    JSONRPCResponse,
    SecurityContext,
    SecurityVerdict,
)
from rich.console import Console


class StdioProxy:
    """
    Transparent stdio wrapper sitting between AI Client and MCP Server child process.
    Cross-platform safe for Windows, macOS, and Linux.
    """

    def __init__(self, command: List[str], policy: Optional[MCPShieldPolicy] = None):
        self.command = command
        self.engine = SecurityEngine(policy)
        self.console = Console(file=sys.stderr)
        self.context = SecurityContext(
            user_id="local_developer",
            role="developer",
            client_name="stdio_client",
        )
        self.pending_requests: dict[str | int, JSONRPCRequest] = {}

    async def run(self) -> int:
        self.console.print(f"[bold green]🛡️ Fortress active.[/bold green] Wrapping: [cyan]{' '.join(self.command)}[/cyan]")

        # Launch child MCP server process
        process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        loop = asyncio.get_event_loop()

        # Forward stderr from child process to sys.stderr
        async def pipe_stderr():
            while True:
                line = await process.stderr.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()

        # Cross-platform safe async stdin reader using loop.run_in_executor
        async def read_stdin_line() -> str:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            return line

        # Inbound pipeline: stdin (Client) -> process.stdin (Server)
        async def handle_inbound():
            while True:
                line = await read_stdin_line()
                if not line:
                    # Client closed stdin
                    if process.stdin:
                        process.stdin.close()
                    break

                raw_str = line.strip()
                if not raw_str:
                    continue

                try:
                    data = json.loads(raw_str)
                    request = JSONRPCRequest.model_validate(data)
                except Exception:
                    # Pass through non-jsonrpc data directly
                    process.stdin.write(line.encode("utf-8"))
                    await process.stdin.drain()
                    continue

                if request.id is not None:
                    self.pending_requests[request.id] = request

                # Inspect inbound request
                result = self.engine.inspect_inbound(request, self.context)

                if result.verdict == SecurityVerdict.BLOCK:
                    self.console.print(f"[bold red]🚫 BLOCKED Inbound tool call:[/bold red] {request.tool_name} - {result.blocked_reason}")
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": request.id,
                        "error": {
                            "code": -32000,
                            "message": f"Blocked by Fortress Security Firewall: {result.blocked_reason}",
                            "data": [v.model_dump() for v in result.violations],
                        },
                    }
                    self._write_client_stdout(error_resp)
                    continue

                elif result.verdict == SecurityVerdict.REQUIRE_APPROVAL and result.pending_token:
                    pending = self.engine.hitl._pending_approvals.get(result.pending_token)
                    if pending:
                        status = await self.engine.hitl.wait_for_decision(pending)
                        if status != ApprovalStatus.APPROVED:
                            self.console.print(f"[bold red]❌ REJECTED tool execution:[/bold red] {request.tool_name}")
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": request.id,
                                "error": {
                                    "code": -32001,
                                    "message": f"Human-in-the-loop approval denied or timed out for tool '{request.tool_name}'.",
                                },
                            }
                            self._write_client_stdout(error_resp)
                            continue

                # Forward allowed request to MCP Server
                payload_bytes = (json.dumps(data) + "\n").encode("utf-8")
                process.stdin.write(payload_bytes)
                await process.stdin.drain()

        # Outbound pipeline: process.stdout (Server) -> stdout (Client)
        async def handle_outbound():
            while True:
                line = await process.stdout.readline()
                if not line:
                    break

                try:
                    raw_str = line.decode("utf-8").strip()
                    if not raw_str:
                        continue
                    data = json.loads(raw_str)
                    response = JSONRPCResponse.model_validate(data)
                except Exception:
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                    continue

                matching_req = None
                if response.id is not None and response.id in self.pending_requests:
                    matching_req = self.pending_requests.pop(response.id)

                # Intercept tools/list response for Schema Pinning & Rug Pull Defense
                if matching_req and matching_req.method in ("tools/list", "list_tools"):
                    is_valid, schema_violations = self.engine.schema_pinner.inspect_tools_list_response(response)
                    if not is_valid:
                        self.console.print(f"[bold red]🚫 BLOCKED Tool Poisoning Rug Pull in tools/list![/bold red]")
                        for sv in schema_violations:
                            self.console.print(f"  [red]• {sv.reason}[/red]")
                        error_resp = {
                            "jsonrpc": "2.0",
                            "id": response.id,
                            "error": {
                                "code": -32003,
                                "message": f"Blocked by Fortress: Tool Poisoning detected: {schema_violations[0].reason}",
                                "data": [v.model_dump() for v in schema_violations],
                            },
                        }
                        self._write_client_stdout(error_resp)
                        continue

                # Inspect outbound response
                result = self.engine.inspect_outbound(response, matching_req, self.context)

                if result.verdict == SecurityVerdict.REDACTED and result.modified_payload:
                    self.console.print(f"[bold yellow]⚠️ REDACTED Sensitive Data in Outbound tool response[/bold yellow]")
                    self._write_client_stdout(result.modified_payload)
                elif result.verdict == SecurityVerdict.BLOCK:
                    self.console.print(f"[bold red]🚫 BLOCKED Outbound tool response due to malicious injection[/bold red]")
                    error_resp = {
                        "jsonrpc": "2.0",
                        "id": response.id,
                        "error": {
                            "code": -32002,
                            "message": "Blocked by Fortress: Outbound tool output contained dangerous prompt injection payload.",
                        },
                    }
                    self._write_client_stdout(error_resp)
                else:
                    self._write_client_stdout(data)

        try:
            await asyncio.gather(pipe_stderr(), handle_inbound(), handle_outbound())
        except Exception as e:
            self.console.print(f"[bold red]Error in stdio proxy:[/bold red] {e}")
        finally:
            if process.returncode is None:
                process.terminate()
            return await process.wait()

    def _write_client_stdout(self, data: dict) -> None:
        payload = json.dumps(data) + "\n"
        sys.stdout.write(payload)
        sys.stdout.flush()
