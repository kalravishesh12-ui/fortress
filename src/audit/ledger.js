const crypto = require('node:crypto');
const fs = require('node:fs');

class AuditLedger {
  constructor(dbPath = './fortress-audit.db', secretKey = 'fortress_enterprise_hmac_secret_2026') {
    this.dbPath = dbPath;
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
    } catch (e) {
      this.hasSqlite = false;
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

    let prevHash = this.genesisHash;
    if (this.hasSqlite) {
      const row = this.db.prepare('SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1').get();
      if (row) prevHash = row.entry_hash;
    } else if (this.inMemoryChain.length > 0) {
      prevHash = this.inMemoryChain[this.inMemoryChain.length - 1].entryHash;
    }

    const entryHash = this.computeEntryHash(prevHash, now, sessionId, userId, toolName, direction, verdict, payloadHash);
    const signature = this.signHash(entryHash);

    if (this.hasSqlite) {
      const stmt = this.db.prepare(`
        INSERT INTO audit_chain (
          timestamp, session_id, user_id, tool_name, direction,
          verdict, violations_json, payload_hash, prev_hash, entry_hash, signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(now, sessionId, userId, toolName, direction, verdict, violationsJson, payloadHash, prevHash, entryHash, signature);
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
}

module.exports = { AuditLedger };
