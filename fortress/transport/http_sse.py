"""
HTTP + SSE Remote Gateway & Administration Server for Fortress.
"""

from __future__ import annotations
import asyncio
import json
import os
import urllib.parse
from typing import Any, Dict, Optional, Union
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from fortress.config import MCPShieldPolicy, load_policy
from fortress.core.engine import SecurityEngine
from fortress.core.models import (
    JSONRPCRequest,
    JSONRPCResponse,
    SecurityContext,
    SecurityVerdict,
)
from fortress.dashboard.app import create_dashboard_router


class KillSwitchRequest(BaseModel):
    active: bool


class HITLActionRequest(BaseModel):
    token: str
    approver: Optional[str] = "admin_user"
    rejecter: Optional[str] = "admin_user"
    reason: Optional[str] = "Rejected by administrator"


class SimulateRequest(BaseModel):
    payload: str


class ToolCallProxyRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}
    auth_token: Optional[str] = None
    session_id: Optional[str] = None


def create_gateway_app(policy_path: Optional[Union[str, MCPShieldPolicy]] = None) -> FastAPI:
    if isinstance(policy_path, MCPShieldPolicy):
        policy = policy_path
    else:
        policy = load_policy(policy_path)
    engine = SecurityEngine(policy)

    app = FastAPI(
        title="Fortress Gateway",
        version="1.0.0",
        description="Enterprise MCP Security Gateway & Deterministic Agent Firewall",
    )


    # Anti-DNS Rebinding and CSRF validation middleware (GHSA-46gc-mwh4-cc5r protection)
    @app.middleware("http")
    async def validate_host_and_origin(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0].lower()
        allowed_hosts = {"localhost", "127.0.0.1", "::1", "testserver"}
        
        # Verify Host header
        if host and host not in allowed_hosts:
            return JSONResponse(
                status_code=403,
                content={"error": f"Forbidden: Invalid Host header '{host}' (Anti-DNS Rebinding Protection)"}
            )

        # Verify Origin header for cross-origin browser requests
        origin = request.headers.get("origin")
        if origin:
            parsed_origin = urllib.parse.urlparse(origin)
            origin_host = (parsed_origin.hostname or "").lower()
            if origin_host not in allowed_hosts:
                return JSONResponse(
                    status_code=403,
                    content={"error": f"Forbidden: Cross-Origin request from '{origin}' blocked (Anti-CSRF Protection)"}
                )

        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach Dashboard router
    app.include_router(create_dashboard_router())

    # --- MCP SSE Transport Endpoints ---

    @app.get("/sse")
    async def mcp_sse_transport(request: Request):
        session_id = request.query_params.get("session_id", f"sess_{os.urandom(6).hex()}")

        async def event_generator():
            yield {
                "event": "endpoint",
                "data": f"/message?session_id={session_id}",
            }
            while True:
                if await request.is_disconnected():
                    break
                await asyncio.sleep(15.0)
                yield {"event": "ping", "data": "keep-alive"}

        return EventSourceResponse(event_generator())

    @app.post("/message")
    async def mcp_message_handler(request: Request):
        session_id = request.query_params.get("session_id", "default_session")
        auth_token = request.headers.get("Authorization", "").replace("Bearer ", "").strip() or None
        
        try:
            body = await request.json()
            rpc_req = JSONRPCRequest.model_validate(body)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON-RPC 2.0 payload: {e}")

        context = SecurityContext(
            session_id=session_id,
            user_id="sse_agent",
            role="agent",
            client_name="sse_client",
        )

        inbound_res = engine.inspect_inbound(rpc_req, context, auth_token=auth_token)
        if inbound_res.verdict == SecurityVerdict.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "id": rpc_req.id,
                    "error": {
                        "code": -32000,
                        "message": f"Blocked by Fortress: {inbound_res.blocked_reason}",
                        "violations": [v.model_dump() for v in inbound_res.violations],
                    },
                },
            )

        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": rpc_req.id,
                "result": {"status": "authorized", "verdict": inbound_res.verdict.value},
            }
        )

    # --- REST Tool Call Proxy ---

    @app.post("/v1/proxy/tools/call")
    async def proxy_tool_call(req: ToolCallProxyRequest):
        rpc_req = JSONRPCRequest(
            method="tools/call",
            params={"name": req.tool, "arguments": req.arguments},
        )
        context = SecurityContext(
            session_id=req.session_id or f"sess_{os.urandom(6).hex()}",
            user_id="rest_agent",
            role="agent",
        )

        inbound_res = engine.inspect_inbound(rpc_req, context, auth_token=req.auth_token)
        if inbound_res.verdict == SecurityVerdict.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",
                    "reason": inbound_res.blocked_reason,
                    "violations": [v.model_dump() for v in inbound_res.violations],
                },
            )
        elif inbound_res.verdict == SecurityVerdict.REQUIRE_APPROVAL:
            return JSONResponse(
                status_code=202,
                content={
                    "status": "pending_approval",
                    "token": inbound_res.pending_token,
                    "message": "Sensitive tool call requires human authorization.",
                },
            )

        return JSONResponse(
            content={
                "status": "allowed",
                "tool": req.tool,
                "verdict": inbound_res.verdict.value,
                "latency_ms": inbound_res.latency_ms,
            }
        )

    # --- Admin & Dashboard APIs ---

    @app.get("/api/v1/stats")
    async def get_dashboard_stats():
        cb_stats = engine.circuit_breaker.get_stats()
        ledger_stats = engine.audit_ledger.get_stats()
        return {**cb_stats, **ledger_stats}

    @app.get("/api/v1/audit/logs")
    async def get_audit_logs(limit: int = 50, offset: int = 0):
        logs = engine.audit_ledger.get_recent_entries(limit=limit, offset=offset)
        return {"logs": logs}

    @app.get("/api/v1/audit/verify")
    async def verify_audit_ledger():
        is_valid, errors = engine.audit_ledger.verify_integrity()
        return {"is_valid": is_valid, "errors": errors}

    @app.get("/api/v1/hitl/pending")
    async def list_pending_approvals():
        pending = engine.hitl.list_pending()
        return {"pending": pending}

    @app.post("/api/v1/hitl/approve")
    async def approve_hitl(action: HITLActionRequest):
        success = engine.hitl.approve(action.token, approver=action.approver or "admin")
        return {"success": success}

    @app.post("/api/v1/hitl/reject")
    async def reject_hitl(action: HITLActionRequest):
        success = engine.hitl.reject(action.token, rejecter=action.rejecter or "admin", reason=action.reason or "Rejected")
        return {"success": success}

    @app.post("/api/v1/admin/killswitch")
    async def set_kill_switch(action: KillSwitchRequest):
        engine.circuit_breaker.set_kill_switch(action.active)
        return {"kill_switch_active": engine.circuit_breaker.is_kill_switch_active()}

    @app.get("/api/v1/policy/raw")
    async def get_raw_policy():
        if policy_path and os.path.exists(policy_path):
            with open(policy_path, "r", encoding="utf-8") as f:
                return Response(content=f.read(), media_type="text/yaml")
        if os.path.exists("fortress-policy.yaml"):
            with open("fortress-policy.yaml", "r", encoding="utf-8") as f:
                return Response(content=f.read(), media_type="text/yaml")
        return Response(content="# Default in-memory policy", media_type="text/yaml")


    @app.get("/api/v1/schemas/pins")
    async def get_schema_pins():
        """Wedge 1: Retrieve all cryptographically pinned tool schemas and HMAC signatures."""
        return {
            "pinned_count": engine.schema_pinner.pinned_tools_count,
            "pins": engine.schema_pinner.get_pins_summary(),
        }

    @app.delete("/api/v1/schemas/pins")
    async def clear_schema_pins():
        """Wedge 1: Clear pinned schemas."""
        engine.schema_pinner.clear_pins()
        return {"status": "cleared", "pinned_count": 0}

    @app.get("/api/v1/sessions/taint")
    async def get_tainted_sessions():
        """Wedge 2: Retrieve stateful session data lineage and active taint records."""
        return {
            "tainted_sessions": [
                {
                    "session_id": sid,
                    "taint_sources": sources,
                    "is_tainted": True,
                }
                for sid, sources in engine._tainted_sessions.items()
            ]
        }

    @app.post("/api/v1/simulate")
    async def simulate_payload(sim: SimulateRequest):
        payload_text = sim.payload

        test_req = JSONRPCRequest(
            method="tools/call",
            params={"name": "test_scanner", "arguments": {"target": payload_text, "url": payload_text}},
        )
        context = SecurityContext(session_id="sim_session", user_id="tester", role="developer")
        in_res = engine.inspect_inbound(test_req, context)

        if in_res.verdict == SecurityVerdict.BLOCK:
            return {
                "verdict": "BLOCK",
                "reason": in_res.blocked_reason,
                "violations": [v.model_dump() for v in in_res.violations],
            }

        test_resp = JSONRPCResponse(result={"output": payload_text})
        out_res = engine.inspect_outbound(test_resp, test_req, context)

        sanitized_str = out_res.modified_payload.get("result", {}).get("output", "") if out_res.modified_payload else payload_text

        return {
            "verdict": out_res.verdict.value,
            "sanitized": sanitized_str,
            "violations": [v.model_dump() for v in out_res.violations],
        }

    return app
