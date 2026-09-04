const crypto = require('node:crypto');

const RiskLevel = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
};

const SecurityVerdict = {
  ALLOW: 'ALLOW',
  BLOCK: 'BLOCK',
  REQUIRE_APPROVAL: 'REQUIRE_APPROVAL',
  REDACTED: 'REDACTED',
};

class SecurityContext {
  constructor(options = {}) {
    this.sessionId = options.sessionId || 'sess_' + crypto.randomBytes(6).toString('hex');
    this.userId = options.userId || 'developer';
    this.role = options.role || 'developer';
    this.tenantId = options.tenantId || null;
    this.clientName = options.clientName || 'stdio-client';
    this.timestamp = options.timestamp || Date.now() / 1000;
    this.isTainted = options.isTainted || false;
    this.taintSources = options.taintSources || [];
  }
}

class ViolationRecord {
  constructor(ruleName, riskLevel, reason, details = {}) {
    this.ruleName = ruleName;
    this.riskLevel = riskLevel;
    this.reason = reason;
    this.details = details;
  }
}

class InspectionResult {
  constructor(verdict, violations = [], options = {}) {
    this.verdict = verdict;
    this.violations = violations;
    this.isAllowed = verdict === SecurityVerdict.ALLOW || verdict === SecurityVerdict.REDACTED;
    this.isBlocked = verdict === SecurityVerdict.BLOCK;
    this.requiresApproval = verdict === SecurityVerdict.REQUIRE_APPROVAL;
    this.latencyMs = options.latencyMs || 0;
    this.modifiedPayload = options.modifiedPayload || null;
    this.blockedReason = options.blockedReason || (violations[0]?.reason || null);
    this.pendingToken = options.pendingToken || null;
  }
}

module.exports = {
  RiskLevel,
  SecurityVerdict,
  SecurityContext,
  ViolationRecord,
  InspectionResult,
};
