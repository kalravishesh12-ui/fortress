const fs = require('node:fs');
const path = require('node:path');
const { RiskLevel, ViolationRecord } = require('./models');

class PathGuard {
  constructor(options = {}) {
    this.allowedBases = (options.allowedBases || ['.']).map(p => path.resolve(p));
    this.blockedPaths = [
      '.ssh', 'id_rsa', 'id_ed25519', '/etc/passwd', '/etc/shadow',
      '/etc/sudoers', 'SAM', '.aws/credentials', '.env', '.git/config'
    ];
    this.windowsReserved = new Set([
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]);
  }

  inspectArguments(args) {
    const strings = this._extractStrings(args);
    const violations = [];
    for (const s of strings) {
      const v = this._checkString(s);
      if (v) violations.push(v);
    }
    return violations;
  }

  _extractStrings(data) {
    const out = [];
    if (typeof data === 'string') {
      out.push(data);
    } else if (Array.isArray(data)) {
      for (const item of data) out.push(...this._extractStrings(item));
    } else if (data && typeof data === 'object') {
      for (const val of Object.values(data)) out.push(...this._extractStrings(val));
    }
    return out;
  }

  _checkString(raw) {
    const s = raw.trim();
    if (/^(?:https?|ftp|ws|wss):\/\//i.test(s)) return null;

    let decoded = s;
    try { decoded = decodeURIComponent(s); } catch (e) {}
    let doubleDecoded = decoded;
    try { doubleDecoded = decodeURIComponent(decoded); } catch (e) {}

    // 1. Null-byte injection
    if (s.includes('\x00') || decoded.includes('\x00') || /%00/i.test(s)) {
      return new ViolationRecord('path_null_byte_injection', RiskLevel.CRITICAL, 'Null byte injection detected in path argument.');
    }

    // 2. Traversal sequences
    if (s.includes('..') || decoded.includes('..') || doubleDecoded.includes('..') || /%2e%2e/i.test(s)) {
      return new ViolationRecord('path_traversal_detected', RiskLevel.CRITICAL, "Path traversal sequence '..' detected in tool argument.");
    }

    // 3. Windows DOS reserved device names
    const baseName = path.basename(s.replace(/\\/g, '/')).split('.')[0].toUpperCase();
    if (this.windowsReserved.has(baseName)) {
      return new ViolationRecord('path_reserved_device_blocked', RiskLevel.CRITICAL, `Target path references Windows reserved system device '${baseName}'.`);
    }

    // 4. NTFS Alternate Data Streams
    const normalized = s.replace(/\\/g, '/');
    const withoutDrive = normalized.replace(/^[a-zA-Z]:/, '');
    if (withoutDrive.includes(':')) {
      return new ViolationRecord('path_alternate_data_stream_blocked', RiskLevel.CRITICAL, 'NTFS Alternate Data Stream access detected.');
    }

    // 5. Sensitive system targets
    const normLower = normalized.toLowerCase();
    for (const b of this.blockedPaths) {
      if (normLower.includes(b.toLowerCase())) {
        return new ViolationRecord('path_sensitive_target_blocked', RiskLevel.CRITICAL, `Access to sensitive target '${b}' is forbidden.`);
      }
    }

    // 6. Symlink canonicalization
    try {
      if (fs.existsSync(s)) {
        const real = fs.realpathSync(s).replace(/\\/g, '/').toLowerCase();
        for (const b of this.blockedPaths) {
          if (real.includes(b.toLowerCase())) {
            return new ViolationRecord('path_symlink_escape_blocked', RiskLevel.CRITICAL, `Path resolves via symlink to forbidden target '${real}'.`);
          }
        }
      }
    } catch (e) {}

    return null;
  }
}

module.exports = { PathGuard };
