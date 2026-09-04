# Security Policy: Fortress MCP Shield

## Supported Versions

Only the latest major and minor releases of Fortress are actively supported with security patches:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

The Fortress team takes the security of our deterministic MCP security gateway seriously. If you discover a vulnerability or potential security bypass (e.g., in taint-tracking, SSRF guards, schema pinning, or secret detection), please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for undisclosed security vulnerabilities.
2. Email your findings directly to the security team at **security@fortress-mcp.org** (or use GitHub Private Vulnerability Reporting via the Security tab).
3. Include the following details to help us triage quickly:
   - Type of vulnerability (e.g., SSRF bypass, path traversal bypass, taint forgery, timing side-channel, schema mutation collision).
   - Component affected (`src/core/*`, `fortress/core/*`, `fortress/transport/*`).
   - Detailed proof-of-concept (PoC) script, JSON-RPC payload, or reproduction steps.
   - Any proposed remediation or patch.

### Response SLA

- **Initial Acknowledgement**: Within 24-48 hours.
- **Triage & Assessment**: Within 72 hours.
- **Fix & Disclosure**: Within 14 to 30 business days depending on severity. Critical zero-day issues receive prioritized hotfixes.

## Hardening Guidelines for Production Deployments

When deploying Fortress in enterprise or staging environments, ensure the following hardening practices are followed:

1. **Configure `FORTRESS_HMAC_SECRET`**:
   Never use default keys in production. Set a cryptographically secure, high-entropy secret (at least 32 bytes) in your environment variables:
   ```bash
   export FORTRESS_HMAC_SECRET="$(openssl rand -hex 32)"
   ```
2. **Strict File Permissions**:
   Ensure `fortress-audit.db` and SQLite WAL files are readable and writable only by the dedicated runtime service user (e.g., `chmod 600 fortress-audit.db*`).
3. **Transport Security**:
   Always place the HTTP/SSE gateway behind a TLS-terminating reverse proxy (Nginx, Envoy, Caddy) or enable mTLS for inter-service communication.
4. **Policy Principle of Least Privilege**:
   Audit `fortress-policy.yaml` before deployment to ensure `allowed_tools` and `denied_tools` align with your organization's least-privilege boundary.
