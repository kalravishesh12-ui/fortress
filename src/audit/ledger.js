const crypto = require('node:crypto');
const fs = require('node:fs');

class AuditLedger {
  constructor(dbPath = './fortress-audit.db', secretKey = process.env.FORTRESS_HMAC_SECRET || 'fortress_enterprise_hmac_secret_2026') {
    this.dbPath = dbPath;
    if (process.env.NODE_ENV === 'production' && !process.env.FORTRESS_HMAC_SECRET && secretKey === 'fortress_enterprise_hmac_secret_2026') {
      console.warn('[Fortress:SecurityWarning] Running in production without FORTRESS_HMAC_SECRET set. Using default secret is insecure.');
    }
    this.secretKey = Buffer.from(secretKey, 'utf-8');
    this.genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.inMemoryChain = [];
    this._initDatabase();
  }

  _initDatabase() {
    try {
      const { DatabaseSync } = require('node:sqlite');
      this.db = new DatabaseSync(this.dbPath);
      this.db.exec(`
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA foreign_keys=ON;
        PRAGMA busy_timeout=30000;
        CREATE TABLE IF NOT EXISTS audit_chain (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          timestamp REAL NOT NULL,
          session_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          tool_name TEXT NOT NULL,
          direction TEXT NOT NULL,
          verdict TEXT NOT NULL,
          violations_json TEXT NOT NULL,
          payload_hash TEXT NOT NULL,
          prev_hash TEXT NOT NULL,
          entry_hash TEXT NOT NULL,
          signature TEXT NOT NULL
        );
      `);
      this.hasSqlite = true;
      this.getLastStmt = this.db.prepare('SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1');
      const row = this.getLastStmt.get();
      this.lastEntryHash = row ? row.entry_hash : this.genesisHash;
      this.insertStmt = this.db.prepare(`
        INSERT INTO audit_chain (
          timestamp, session_id, user_id, tool_name, direction,
          verdict, violations_json, payload_hash, prev_hash, entry_hash, signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
    } catch (e) {
      this.hasSqlite = false;
      this.lastEntryHash = this.genesisHash;
    }
  }

  computeEntryHash(prevHash, timestamp, sessionId, userId, toolName, direction, verdict, payloadHash) {
    const dataBlock = `${prevHash}|${Number(timestamp).toFixed(6)}|${sessionId}|${userId}|${toolName}|${direction}|${verdict}|${payloadHash}`;
    return crypto.createHash('sha256').update(dataBlock).digest('hex');
  }

  signHash(entryHash) {
    return crypto.createHmac('sha256', this.secretKey).update(entryHash).digest('hex');
  }

  logEvent(sessionId, userId, toolName, direction, verdict, violations, payload) {
    const now = Date.now() / 1000;
    const payloadHash = crypto.createHash('sha256').update(JSON.stringify(payload || {})).digest('hex');
    const violationsJson = JSON.stringify(violations || []);

    let prevHash = this.lastEntryHash || this.genesisHash;
    let entryHash = '';
    let signature = '';

    if (this.hasSqlite) {
      this.db.exec('BEGIN EXCLUSIVE;');
      try {
        const row = this.getLastStmt.get();
        prevHash = row ? row.entry_hash : (this.lastEntryHash || this.genesisHash);
        entryHash = this.computeEntryHash(prevHash, now, sessionId, userId, toolName, direction, verdict, payloadHash);
        signature = this.signHash(entryHash);

        this.insertStmt.run(now, sessionId, userId, toolName, direction, verdict, violationsJson, payloadHash, prevHash, entryHash, signature);
        this.db.exec('COMMIT;');
        this.lastEntryHash = entryHash;
      } catch (err) {
        try { this.db.exec('ROLLBACK;'); } catch (_) {}
        throw err;
      }
    } else {
      entryHash = this.computeEntryHash(prevHash, now, sessionId, userId, toolName, direction, verdict, payloadHash);
      signature = this.signHash(entryHash);
      this.lastEntryHash = entryHash;
    }

    const record = {
      timestamp: now,
      sessionId,
      userId,
      toolName,
      direction,
      verdict,
      violations,
      prevHash,
      entryHash,
      signature,
    };
    this.inMemoryChain.push(record);
    return record;
  }

  pruneOldEntries(days = 90) {
    if (!this.hasSqlite) return 0;
    const cutoff = (Date.now() / 1000) - (days * 86400);
    this.db.exec('BEGIN EXCLUSIVE;');
    try {
      const res = this.db.prepare('DELETE FROM audit_chain WHERE timestamp < ?').run(cutoff);
      this.db.exec('COMMIT;');
      if (res && res.changes > 1000) {
        try { this.db.exec('VACUUM;'); } catch (_) {}
      }
      return res ? res.changes : 0;
    } catch (err) {
      try { this.db.exec('ROLLBACK;'); } catch (_) {}
      throw err;
    }
  }

  verifyIntegrity() {
    const errors = [];
    let expectedPrev = this.genesisHash;

    if (this.hasSqlite) {
      const rows = this.db.prepare('SELECT * FROM audit_chain ORDER BY id ASC').all();
      for (const row of rows) {
        if (row.prev_hash !== expectedPrev) {
          errors.push(`Entry #${row.id}: Broken chain! prev_hash '${row.prev_hash}' != expected '${expectedPrev}'`);
        }
        const computed = this.computeEntryHash(
          row.prev_hash, row.timestamp, row.session_id, row.user_id,
          row.tool_name, row.direction, row.verdict, row.payload_hash
        );
        if (computed !== row.entry_hash) {
          errors.push(`Entry #${row.id}: Hash mismatch! Computed '${computed}' != stored '${row.entry_hash}'`);
        }
        const sig = this.signHash(row.entry_hash);
        if (sig !== row.signature) {
          errors.push(`Entry #${row.id}: Tampered signature detected!`);
        }
        expectedPrev = row.entry_hash;
      }
    }
    return { isValid: errors.length === 0, errors };
  }

  exportCEF(entry) {
    const severity = entry.verdict === 'BLOCK' ? 10 : 1;
    return `CEF:0|MCPSecurity|Fortress|1.0|${entry.verdict}|${entry.toolName}|${severity}|src=${entry.userId} suser=${entry.sessionId} act=${entry.direction} cs1=${entry.entryHash} cs1Label=EntryHash cs2=${entry.prevHash} cs2Label=PrevHash`;
  }

  exportSTIXBundle(entries) {
    const bundleId = `bundle--${crypto.randomUUID()}`;
    const stixObjects = [];

    for (const entry of entries) {
      const tsStr = new Date((entry.timestamp || (Date.now() / 1000)) * 1000).toISOString();
      const verdict = entry.verdict || 'ALLOW';
      const toolName = entry.toolName || entry.tool_name || 'unknown';
      const userId = entry.userId || entry.user_id || 'unknown';
      const sessionId = entry.sessionId || entry.session_id || 'unknown';

      stixObjects.push({
        type: 'observed-data',
        id: `observed-data--${crypto.randomUUID()}`,
        created: tsStr,
        modified: tsStr,
        first_observed: tsStr,
        last_observed: tsStr,
        number_observed: 1,
        objects: {
          '0': { type: 'user-account', user_id: userId, account_login: sessionId },
          '1': {
            type: 'network-traffic',
            protocol: 'mcp-jsonrpc',
            extensions: {
              'x-fortress-event': {
                verdict,
                tool_name: toolName,
                direction: entry.direction || 'INBOUND',
                entry_hash: entry.entryHash || entry.entry_hash || '',
                prev_hash: entry.prevHash || entry.prev_hash || '',
                violations: entry.violations || [],
              }
            }
          }
        }
      });

      if (verdict === 'BLOCK') {
        stixObjects.push({
          type: 'indicator',
          id: `indicator--${crypto.randomUUID()}`,
          created: tsStr,
          modified: tsStr,
          name: `Fortress Block: ${toolName}`,
          description: `MCP Security Gateway blocked call to ${toolName} for session ${sessionId}`,
          pattern: "[network-traffic:extensions.'x-fortress-event'.verdict = 'BLOCK']",
          valid_from: tsStr,
        });
      }
    }

    return JSON.stringify({
      type: 'bundle',
      id: bundleId,
      spec_version: '2.0',
      objects: stixObjects,
    }, null, 2);
  }
}

module.exports = { AuditLedger };
