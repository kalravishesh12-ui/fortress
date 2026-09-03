# 🛡️ MCP-Shield: Enterprise MCP Security Gateway & Deterministic Agent Firewall

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://python.org)
[![Security](https://img.shields.io/badge/Security-Fail--Closed-red.svg)]()
[![Determinism](https://img.shields.io/badge/Firewall-Deterministic_<1ms-brightgreen.svg)]()

**MCP-Shield** is a lightweight, sub-millisecond reverse-proxy and security middleware layer that sits directly between AI clients (*Claude Desktop, Cursor, Enterprise Agent Swarms*) and MCP Tool Servers (*Database connectors, Shell executors, Filesystems, Internal APIs*).

Its mission: **Break the "Lethal Trifecta"** (unrestricted tool access, data exfiltration, indirect prompt injection) deterministically, before malicious payloads reach production infrastructure or models.

---

## 🏗️ Architecture & Dual-Stage Pipeline

MCP-Shield enforces a **fail-closed security model** across two synchronized inspection pipelines:

```
[ AI Client (Claude / Cursor / Swarm) ]
                 │
                 ▼ (Inbound JSON-RPC 2.0 Request)
┌────────────────────────────────────────────────────────┐
│  INBOUND INSPECTION PIPELINE (< 1ms Latency)           │
│  1. Kill Switch & Circuit Breaker (Global / Session)   │
│  2. Identity & RBAC Token Binding                      │
│  3. Tool Allow / Deny Policy Matching                  │
│  4. Rate Limiter & Session Budget Quota                │
│  5. Path Traversal & Filesystem Sandbox Validator      │
│  6. Egress & SSRF Guard (Cloud IMDS 169.254.169.254)   │
│  7. Human-in-the-Loop (HITL) Authorization Hook        │
└────────────────────────────────────────────────────────┘
                 │
                 ▼ (Forward Safe Call)
[ MCP Tool Server (Filesystem, Postgres, Shell, Git) ]
                 │
                 ▼ (Raw Server Output)
┌────────────────────────────────────────────────────────┐
│  OUTBOUND INSPECTION PIPELINE (< 5ms Latency)          │
│  1. Secret & Credential Scanner (Regex + Shannon)      │
│  2. PII Redaction Engine (SSN, Credit Cards, Luhn)     │
│  3. Indirect Prompt Injection & Jailbreak Detector     │
│  4. Cryptographic Hash-Chained Audit Ledger (SQLite)   │
└────────────────────────────────────────────────────────┘
                 │
                 ▼ (Sanitized Output)
[ AI Client Context Window ]
```

---

## 🎯 The Three Foundational Production Wedges

### 1. 🛡️ Wedge 1: Tool Poisoning & Dynamic "Rug Pull" Protection
- **The Problem:** Naive proxies only inspect static arguments in `tools/call`. If a compromised MCP server silently modifies its description in `tools/list` after the user approves it (the *"Tool Poisoning Rug Pull"*), argument-only firewalls miss it completely.
- **The MCP-Shield Fix:** Implements **Stage 0 Immutable Schema Pinning** ([`SchemaPinner`](file:///C:/Users/kalra/mcp-shield/mcp_shield/core/schema_pinner.py)). Computes SHA-256 fingerprints of canonical tool schemas and cryptographically signs them with HMAC-SHA256 upon first connection. If a tool definition or description mutates dynamically at runtime, the gateway trips the circuit breaker and aborts execution.
- **CLI Command:** `mcp-shield inspect-schema <tools_definition.json>`

### 2. ⛓️ Wedge 2: Stateful Taint-Tracking & Compound Tool Chaining
- **The Problem:** Existing firewalls evaluate each tool call in isolation. Call 1 (`read_file`) passes. Call 2 (`send_slack_message`) passes. Together, they execute an unauthorized data exfiltration attack chain.
- **The MCP-Shield Fix:** Tracks session data lineage ([`SecurityContext.is_tainted`](file:///C:/Users/kalra/mcp-shield/mcp_shield/core/models.py)). When an agent ingests private context in Step 1 (`read_*`, `query_*`), the session is flagged as tainted. If the session attempts external egress in Step 2 (`send_*`, `post_*`, `upload_*`, `webhook_*`), the call is intercepted and gated by Human-in-the-Loop (HITL) authorization.
- **CLI Command:** `mcp-shield taint-lineage <session_id>`

### 3. 🌐 Wedge 3: Network-Level SSRF & DNS Rebinding Immunity
- **The Problem:** Proxies that validate URLs via string matching or application-level DNS are vulnerable to **Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding** (using 0-second TTL domains that resolve to public IPs during check, then flip to `169.254.169.254` during connection).
- **The MCP-Shield Fix:** Implements **Socket-Pinned Egress Validation** ([`SSRFGuard.open_pinned_connection`](file:///C:/Users/kalra/mcp-shield/mcp_shield/core/ssrf_guard.py)). Resolves DNS once, validates all destination IPs against private/cloud metadata ranges, and forces the transport layer socket to connect directly to that pinned IP while preserving TLS SNI and the original `Host` header.
- **CVE-2025 Protection:** Local gateway (`localhost:9090`) enforces strict `Host` and `Origin` header validation, neutralizing browser-based DNS rebinding attacks (GHSA-46gc-mwh4-cc5r).

---

## 📦 Quickstart

### 1. Installation

```bash
cd mcp-shield
pip install -e .
```

### 2. Transparent `stdio` Wrapper (Claude Desktop / Cursor)

Wrap any MCP server CLI command transparently:

```bash
# Wrap a local filesystem server
mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem ./safe-dir
```

#### Claude Desktop Configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "filesystem-protected": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--policy", "C:/Users/kalra/mcp-shield/mcp-policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "C:/Users/kalra/safe-dir"
      ]
    }
  }
}
```

### 3. Remote Gateway & Web Dashboard Mode

Launch the centralized HTTP+SSE reverse-proxy and dashboard:

```bash
mcp-shield serve --port 9090
```

- **Web Dashboard:** [http://localhost:9090](http://localhost:9090)
- **MCP SSE Transport:** `http://localhost:9090/sse`
- **Tool Call Proxy:** `http://localhost:9090/v1/proxy/tools/call`

---

## 🛠️ CLI Reference

| Command | Description |
|---|---|
| `mcp-shield wrap -- <cmd>` | Wrap a local MCP server child process over `stdio`. |
| `mcp-shield serve --port 9090` | Launch HTTP+SSE Gateway Server and Web Dashboard. |
| `mcp-shield verify-audit` | Verify the cryptographic hash chain of the audit database. |
| `mcp-shield init-policy` | Generate a fresh, production-ready `mcp-policy.yaml`. |
| `mcp-shield test-payload <str>` | Fire a test string or file against security scanners. |
| `mcp-shield version` | Display package version. |

---

## ⚙️ Declarative Policy Configuration (`mcp-policy.yaml`)

```yaml
version: "1.0"

kill_switch:
  enabled: false

circuit_breaker:
  enabled: true
  max_violations_per_session: 5
  cooldown_seconds: 60

rate_limiting:
  enabled: true
  calls_per_minute: 60
  max_session_cost_usd: 10.0

rbac:
  enabled: true
  default_role: "agent"
  roles:
    admin:
      allowed_tools: ["*"]
    developer:
      allowed_tools: ["read_*", "get_*", "list_*", "write_*"]
      denied_tools: ["*exec*", "*eval*", "delete_database"]
      require_approval: ["write_*"]
    readonly:
      allowed_tools: ["read_*", "get_*", "list_*"]
      denied_tools: ["write_*", "delete_*", "*exec*"]

tool_policies:
  deny_patterns:
    - "*exec*"
    - "*eval*"
    - "*system*"
    - "delete_database"
  require_approval:
    - "execute_query"
    - "update_*"
    - "transfer_funds"

path_guard:
  enabled: true
  allowed_base_directories: ["."]
  blocked_paths: [".ssh", "id_rsa", "/etc/passwd", "/etc/shadow", "SAM"]

ssrf_guard:
  enabled: true
  blocked_ip_ranges:
    - "169.254.169.254/32"
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "192.168.0.0/16"

outbound_guard:
  scan_secrets: true
  entropy_threshold: 4.5
  mask_pii: true
  pii_types: ["ssn", "credit_card", "email", "phone"]
  scan_prompt_injection: true
  injection_action: "sanitize"

audit_ledger:
  enabled: true
  db_path: "./mcp-shield-audit.db"
```

---

## 🧪 Running the Test Suite

```bash
pytest -v
```

Tests verify:
1. Inbound validation (SSRF, Path Traversal, RBAC, Rate Limiter, Kill Switch, HITL tokens).
2. Outbound redaction (Secrets, Shannon Entropy, PII, Prompt Injections).
3. Cryptographic hash chain verification and tamper detection.
4. HTTP + SSE Gateway endpoints and Admin API.

---

## 📄 License

Apache License 2.0. Built for security-first enterprise agentic AI architectures.
