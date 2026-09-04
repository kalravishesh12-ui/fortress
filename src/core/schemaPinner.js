const crypto = require('node:crypto');
const { RiskLevel, ViolationRecord } = require('./models');

class SchemaPinner {
  constructor(secretKey = process.env.FORTRESS_HMAC_SECRET || 'fortress_enterprise_hmac_secret_2026') {
    if (process.env.NODE_ENV === 'production' && !process.env.FORTRESS_HMAC_SECRET && secretKey === 'fortress_enterprise_hmac_secret_2026') {
      console.warn('[Fortress:SecurityWarning] Running in production without FORTRESS_HMAC_SECRET set. Tool schemas are pinned using default secret.');
    }
    this.secretKey = Buffer.from(secretKey, 'utf-8');
    this.pinnedHashes = new Map();
    this.pinnedSignatures = new Map();
    this.pinnedSchemas = new Map();
  }

  get pinnedCount() {
    return this.pinnedHashes.size;
  }

  computeHash(toolDef) {
    const canonical = {
      name: (toolDef.name || '').trim(),
      description: (toolDef.description || '').trim(),
      inputSchema: toolDef.inputSchema || {},
    };
    const serialized = JSON.stringify(canonical, Object.keys(canonical).sort());
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  signHash(hashStr) {
    return crypto.createHmac('sha256', this.secretKey).update(hashStr).digest('hex');
  }

  pinTool(toolDef) {
    const name = toolDef.name;
    const h = this.computeHash(toolDef);
    const sig = this.signHash(h);
    this.pinnedHashes.set(name, h);
    this.pinnedSignatures.set(name, sig);
    this.pinnedSchemas.set(name, toolDef);
    return h;
  }

  inspectToolsListResponse(response, allowAutoPin = true) {
    const violations = [];
    if (!response || !response.result || !Array.isArray(response.result.tools)) {
      return { isValid: true, violations: [] };
    }

    const tools = response.result.tools;
    for (const tool of tools) {
      if (!tool || !tool.name) continue;
      const toolName = tool.name;
      const desc = tool.description || '';
      const currentHash = this.computeHash(tool);

      // 1. Scan description for embedded prompt injections
      if (/ignore|disregard|forget|override/i.test(desc) && /instructions|prompts|rules/i.test(desc)) {
        violations.push(new ViolationRecord(
          'schema_poisoning_injection_detected',
          RiskLevel.CRITICAL,
          `Tool '${toolName}' description contains prompt injection override directive.`,
          { tool: toolName, snippet: desc.slice(0, 100) }
        ));
      }

      // 2. Check for dynamic schema mutation (Rug Pull)
      if (this.pinnedHashes.has(toolName)) {
        const expectedHash = this.pinnedHashes.get(toolName);
        if (currentHash !== expectedHash) {
          violations.push(new ViolationRecord(
            'schema_poisoning_mutation_detected',
            RiskLevel.CRITICAL,
            `Tool '${toolName}' schema has mutated dynamically after initial authorization (Rug Pull detected).`,
            { tool: toolName, expectedHash, currentHash }
          ));
        }
      } else if (allowAutoPin) {
        this.pinTool(tool);
      }
    }

    return { isValid: violations.length === 0, violations };
  }

  verifyToolCallPin(toolName) {
    if (this.pinnedHashes.size > 0 && !this.pinnedHashes.has(toolName)) {
      return new ViolationRecord(
        'unregistered_tool_call',
        RiskLevel.HIGH,
        `Tool '${toolName}' was not declared or pinned during initial tools/list handshake.`,
        { tool: toolName }
      );
    }
    return null;
  }

  getPinsSummary() {
    const list = [];
    for (const [name, h] of this.pinnedHashes.entries()) {
      list.push({
        tool: name,
        hash: h,
        signature: this.pinnedSignatures.get(name)?.slice(0, 16) + '...',
      });
    }
    return list;
  }
}

module.exports = { SchemaPinner };
