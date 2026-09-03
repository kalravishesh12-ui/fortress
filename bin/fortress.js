#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { StdioProxy } = require('../src/transport/stdio');
const { FortressEngine } = require('../src/core/engine');
const { SecurityContext, SecurityVerdict } = require('../src/core/models');

const args = process.argv.slice(2);
const cmd = args[0];

function printHelp() {
  console.log(`
\x1b[1m\x1b[36m🏰 Fortress: Enterprise MCP Security Gateway & Deterministic Agent Firewall\x1b[0m

Usage:
  npx fortress-mcp <command> [options]

Commands:
  \x1b[32mwrap -- <command...>\x1b[0m      Transparently wrap a local MCP server over stdio
  \x1b[32mtest-payload <text>\x1b[0m       Test an input payload against deterministic filters
  \x1b[32minspect-schema <file>\x1b[0m     Inspect & cryptographically pin a tools/list schema (Wedge 1)
  \x1b[32mtaint-status <session>\x1b[0m    Inspect stateful session data lineage (Wedge 2)
  \x1b[32mverify-audit\x1b[0m               Verify tamper-evident hash-chain integrity
  \x1b[32mversion\x1b[0m                    Print version information
`);
}

if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
  printHelp();
  process.exit(0);
}

if (cmd === 'version' || cmd === '-v' || cmd === '--version') {
  console.log('Fortress version 1.0.0 (Node.js Engine)');
  process.exit(0);
}

if (cmd === 'wrap') {
  const dashIndex = args.indexOf('--');
  const targetArgs = dashIndex !== -1 ? args.slice(dashIndex + 1) : args.slice(1);
  if (targetArgs.length === 0) {
    console.error('\x1b[31mError: No target command specified. Usage: fortress wrap -- <command> [args...]\x1b[0m');
    process.exit(1);
  }
  const proxy = new StdioProxy(targetArgs[0], targetArgs.slice(1));
  proxy.run();
} else if (cmd === 'test-payload') {
  const payload = args.slice(1).join(' ');
  if (!payload) {
    console.error('\x1b[31mError: Please provide payload to test.\x1b[0m');
    process.exit(1);
  }
  const engine = new FortressEngine();
  const ctx = new SecurityContext();
  const req = { method: 'tools/call', params: { name: 'test_tool', arguments: { target: payload, url: payload, path: payload } } };
  const inRes = engine.inspectInbound(req, ctx);
  const resp = { jsonrpc: '2.0', id: 1, result: { data: payload } };
  const outRes = engine.inspectOutbound(resp, req, ctx);

  console.log('\x1b[1m=== Fortress Scan Results ===\x1b[0m');
  console.log(`Inbound Verdict:  ${inRes.verdict === 'ALLOW' ? '\x1b[32mALLOW\x1b[0m' : '\x1b[31m' + inRes.verdict + '\x1b[0m'}`);
  console.log(`Outbound Verdict: ${outRes.verdict === 'ALLOW' ? '\x1b[32mALLOW\x1b[0m' : '\x1b[33m' + outRes.verdict + '\x1b[0m'}`);
  const allViolations = [...inRes.violations, ...outRes.violations];
  if (allViolations.length > 0) {
    console.log('\n\x1b[31mDetected Violations:\x1b[0m');
    for (const v of allViolations) {
      console.log(`  • [${v.riskLevel}] ${v.ruleName}: ${v.reason}`);
    }
  } else {
    console.log('\x1b[32mNo security violations detected. Clean payload.\x1b[0m');
  }
} else if (cmd === 'inspect-schema') {
  const file = args[1];
  if (!file || !fs.existsSync(file)) {
    console.error(`\x1b[31mFile '${file}' not found.\x1b[0m`);
    process.exit(1);
  }
  const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
  const engine = new FortressEngine();
  const resp = { jsonrpc: '2.0', id: 1, result: Array.isArray(data) ? { tools: data } : (data.tools ? data : { tools: [data] }) };
  const { isValid, violations } = engine.schemaPinner.inspectToolsListResponse(resp);

  console.log('\x1b[1m=== MCP Tool Schemas Cryptographic Pins ===\x1b[0m');
  for (const pin of engine.schemaPinner.getPinsSummary()) {
    console.log(`Tool: \x1b[36m${pin.tool}\x1b[0m | Hash: \x1b[32m${pin.hash.slice(0, 24)}...\x1b[0m | Sig: \x1b[35m${pin.signature}\x1b[0m`);
  }
  if (!isValid) {
    console.log('\n\x1b[31mPoisoning Violations Detected:\x1b[0m');
    for (const v of violations) console.log(`  • ${v.ruleName}: ${v.reason}`);
    process.exit(1);
  } else {
    console.log(`\x1b[32m✅ ${engine.schemaPinner.pinnedCount} tool schemas cryptographically pinned and verified safe.\x1b[0m`);
  }
} else if (cmd === 'verify-audit') {
  const engine = new FortressEngine();
  const { isValid, errors } = engine.auditLedger.verifyIntegrity();
  console.log(`Audit Integrity: ${isValid ? '\x1b[32mVERIFIED (100% Tamper-Proof)\x1b[0m' : '\x1b[31mFAILED - TAMPERED\x1b[0m'}`);
  if (!isValid) {
    for (const err of errors) console.log(`  • ${err}`);
    process.exit(1);
  }
} else {
  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}
