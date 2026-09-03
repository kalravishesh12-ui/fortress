const { spawn } = require('node:child_process');
const readline = require('node:readline');
const { FortressEngine } = require('../core/engine');
const { SecurityContext, SecurityVerdict } = require('../core/models');

class StdioProxy {
  constructor(command, args = [], options = {}) {
    this.command = command;
    this.args = args;
    this.engine = new FortressEngine(options);
    this.context = new SecurityContext();
    this.pendingRequests = new Map();
  }

  run() {
    process.stderr.write(`\x1b[32m🛡️ Fortress Active (Node.js Engine)\x1b[0m Wrapping: ${this.command} ${this.args.join(' ')}\n`);

    const child = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'inherit'],
    });

    const clientRl = readline.createInterface({ input: process.stdin, terminal: false });
    const serverRl = readline.createInterface({ input: child.stdout, terminal: false });

    // Client -> Server (Inbound)
    clientRl.on('line', (line) => {
      const s = line.trim();
      if (!s) return;
      let req;
      try {
        req = JSON.parse(s);
      } catch (e) {
        child.stdin.write(line + '\n');
        return;
      }

      if (req.id !== undefined) {
        this.pendingRequests.set(req.id, req);
      }

      // Inspect Inbound
      const res = this.engine.inspectInbound(req, this.context);

      if (res.verdict === SecurityVerdict.BLOCK) {
        process.stderr.write(`\x1b[31m🚫 BLOCKED Inbound tool call:\x1b[0m ${req.params?.name || 'unknown'} - ${res.blockedReason}\n`);
        const errResp = {
          jsonrpc: '2.0',
          id: req.id,
          error: {
            code: -32000,
            message: `Blocked by Fortress Firewall: ${res.blockedReason}`,
            data: res.violations,
          },
        };
        process.stdout.write(JSON.stringify(errResp) + '\n');
        return;
      }

      if (res.verdict === SecurityVerdict.REQUIRE_APPROVAL) {
        process.stderr.write(`\x1b[33m⚠️ GATED Inbound tool call (Taint Exfil Protection):\x1b[0m ${req.params?.name || 'unknown'}\n`);
        const errResp = {
          jsonrpc: '2.0',
          id: req.id,
          error: {
            code: -32001,
            message: `Blocked by Fortress: Compound data exfiltration risk detected. Human sign-off required.`,
            data: res.violations,
          },
        };
        process.stdout.write(JSON.stringify(errResp) + '\n');
        return;
      }

      child.stdin.write(line + '\n');
    });

    // Server -> Client (Outbound)
    serverRl.on('line', (line) => {
      const s = line.trim();
      if (!s) return;
      let resp;
      try {
        resp = JSON.parse(s);
      } catch (e) {
        process.stdout.write(line + '\n');
        return;
      }

      const matchingReq = resp.id !== undefined ? this.pendingRequests.get(resp.id) : null;
      if (resp.id !== undefined) this.pendingRequests.delete(resp.id);

      // Wedge 1: Intercept tools/list for Schema Pinning & Rug Pull Defense
      if (matchingReq && (matchingReq.method === 'tools/list' || matchingReq.method === 'list_tools')) {
        const { isValid, violations } = this.engine.schemaPinner.inspectToolsListResponse(resp);
        if (!isValid) {
          process.stderr.write(`\x1b[31m🚫 BLOCKED Tool Poisoning Rug Pull in tools/list!\x1b[0m\n`);
          const errResp = {
            jsonrpc: '2.0',
            id: resp.id,
            error: {
              code: -32003,
              message: `Blocked by Fortress: Tool Poisoning detected: ${violations[0]?.reason}`,
              data: violations,
            },
          };
          process.stdout.write(JSON.stringify(errResp) + '\n');
          return;
        }
      }

      // Inspect Outbound Response
      const res = this.engine.inspectOutbound(resp, matchingReq, this.context);

      if (res.verdict === SecurityVerdict.REDACTED && res.modifiedPayload) {
        process.stderr.write(`\x1b[33m⚠️ REDACTED Sensitive Data in Outbound tool response\x1b[0m\n`);
        process.stdout.write(JSON.stringify(res.modifiedPayload) + '\n');
      } else {
        process.stdout.write(JSON.stringify(resp) + '\n');
      }
    });

    child.on('exit', (code) => process.exit(code || 0));
  }
}

module.exports = { StdioProxy };
