const { PathGuard } = require('./pathGuard');
const { SSRFGuard } = require('./ssrfGuard');
const { SchemaPinner } = require('./schemaPinner');
const { SecretScanner } = require('./secretScanner');
const { PIIRedactor } = require('./piiRedactor');
const { InjectionDetector } = require('./injectionDetector');
const { AuditLedger } = require('../audit/ledger');
const { SecurityVerdict, InspectionResult, ViolationRecord, RiskLevel } = require('./models');

class FortressEngine {
  constructor(options = {}) {
    this.killSwitchActive = false;
    this.pathGuard = new PathGuard(options.path || {});
    this.ssrfGuard = new SSRFGuard(options.ssrf || {});
    this.schemaPinner = new SchemaPinner(options.secretKey);
    this.secretScanner = new SecretScanner(options.secrets || {});
    this.piiRedactor = new PIIRedactor();
    this.injectionDetector = new InjectionDetector();
    this.auditLedger = new AuditLedger(options.auditDb, options.secretKey);
    this.taintedSessions = new Map(); // sessionId -> [tools]
  }

  inspectInbound(request, context) {
    const start = performance.now();
    const toolName = request?.params?.name || 'unknown_tool';
    const args = request?.params?.arguments || {};
    const violations = [];

    // 1. Kill Switch Check
    if (this.killSwitchActive) {
      const v = new ViolationRecord('global_kill_switch_active', RiskLevel.CRITICAL, 'Global Kill Switch is active. All agent operations are frozen.');
      violations.push(v);
      return this._finalizeInbound(request, context, toolName, SecurityVerdict.BLOCK, violations, start);
    }

    // 2. Denied tool patterns
    if (/shell_exec|eval_code|raw_exec|delete_database|drop_database/i.test(toolName)) {
      const v = new ViolationRecord('tool_policy_denied', RiskLevel.CRITICAL, `Tool '${toolName}' is forbidden by global security policy.`);
      violations.push(v);
      return this._finalizeInbound(request, context, toolName, SecurityVerdict.BLOCK, violations, start);
    }

    // 3. Wedge 2: Stateful Taint-Tracking & Compound Tool Chaining Check
    const sessionTaints = this.taintedSessions.get(context.sessionId) || [];
    const isEgressTool = /egress|send_|post_|upload_|webhook_|email_|export_/i.test(toolName);
    if (sessionTaints.length > 0 && isEgressTool) {
      context.isTainted = true;
      context.taintSources = [...sessionTaints];
      const v = new ViolationRecord(
        'compound_taint_egress_violation',
        RiskLevel.CRITICAL,
        `Session '${context.sessionId}' is tainted by sensitive context from [${sessionTaints.join(', ')}]; downstream egress tool '${toolName}' requires human authorization.`
      );
      violations.push(v);
      return this._finalizeInbound(request, context, toolName, SecurityVerdict.REQUIRE_APPROVAL, violations, start, {
        pendingToken: 'hitl_tok_' + Math.random().toString(36).substring(2, 10),
      });
    }

    // 4. Path Traversal Guard
    const pathViolations = this.pathGuard.inspectArguments(args);
    if (pathViolations.length > 0) {
      violations.push(...pathViolations);
      return this._finalizeInbound(request, context, toolName, SecurityVerdict.BLOCK, violations, start);
    }

    // 5. SSRF Guard
    const ssrfViolations = this.ssrfGuard.inspectArguments(args);
    if (ssrfViolations.length > 0) {
      violations.push(...ssrfViolations);
      return this._finalizeInbound(request, context, toolName, SecurityVerdict.BLOCK, violations, start);
    }

    // Allowed
    return this._finalizeInbound(request, context, toolName, SecurityVerdict.ALLOW, violations, start);
  }

  _finalizeInbound(request, context, toolName, verdict, violations, start, extra = {}) {
    const latencyMs = performance.now() - start;
    this.auditLedger.logEvent(context.sessionId, context.userId, toolName, 'INBOUND', verdict, violations, request);
    return new InspectionResult(verdict, violations, { latencyMs, ...extra });
  }

  inspectOutbound(response, request, context) {
    const start = performance.now();
    const toolName = request?.params?.name || 'response';
    const violations = [];

    if (!response || !response.result) {
      return new InspectionResult(SecurityVerdict.ALLOW, [], { latencyMs: performance.now() - start });
    }

    let current = response.result;
    let verdict = SecurityVerdict.ALLOW;

    // Wedge 2: Record taint if tool matches sensitive read
    if (/ingest|read_|query_|fetch_|get_|download_|cat_/i.test(toolName)) {
      if (!this.taintedSessions.has(context.sessionId)) {
        this.taintedSessions.set(context.sessionId, []);
      }
      const list = this.taintedSessions.get(context.sessionId);
      if (!list.includes(toolName)) list.push(toolName);
      context.isTainted = true;
      context.taintSources = [...list];
    }

    // 1. Secret scanning & base64 normalization
    const secRes = this.secretScanner.scanAndRedact(current);
    if (secRes.violations.length > 0) {
      violations.push(...secRes.violations);
      current = secRes.sanitized;
      verdict = SecurityVerdict.REDACTED;
    }

    // 2. PII Redaction
    const piiRes = this.piiRedactor.redact(current);
    if (piiRes.violations.length > 0) {
      violations.push(...piiRes.violations);
      current = piiRes.sanitized;
      verdict = SecurityVerdict.REDACTED;
    }

    // 3. Prompt Injection Detection
    const injRes = this.injectionDetector.inspect(current);
    if (injRes.violations.length > 0) {
      violations.push(...injRes.violations);
      current = injRes.sanitized;
      verdict = SecurityVerdict.REDACTED;
    }

    const modifiedPayload = { ...response, result: current };
    const latencyMs = performance.now() - start;
    this.auditLedger.logEvent(context.sessionId, context.userId, toolName, 'OUTBOUND', verdict, violations, modifiedPayload);
    return new InspectionResult(verdict, violations, { latencyMs, modifiedPayload });
  }
}

module.exports = { FortressEngine };
