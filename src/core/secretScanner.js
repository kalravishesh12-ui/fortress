const { RiskLevel, ViolationRecord } = require('./models');

class SecretScanner {
  constructor(options = {}) {
    this.entropyThreshold = options.entropyThreshold || 4.5;
    this.patterns = {
      AWS_ACCESS_KEY: /\b(AKIA[0-9A-Z]{16})\b/g,
      AWS_SECRET_KEY: /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
      GITHUB_TOKEN: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b|\b(github_pat_[A-Za-z0-9_]{82})\b/g,
      OPENAI_API_KEY: /\b(sk-[a-zA-Z0-9_-]{32,}|sk-proj-[a-zA-Z0-9_-]{32,})\b/g,
      ANTHROPIC_API_KEY: /\b(sk-ant-[a-zA-Z0-9_-]{32,})\b/g,
      STRIPE_KEY: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g,
      SLACK_TOKEN: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
      JWT_TOKEN: /\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)\b/g,
      PRIVATE_KEY: /-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)? PRIVATE KEY[^-]*-----/g,
    };
    this.base64Pattern = /(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})/g;
    this.entropyTokenPattern = /\S{20,256}/g;
  }

  calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const map = {};
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      map[c] = (map[c] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(map)) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  scanAndRedact(data) {
    const violations = [];
    const sanitized = this._processData(data, violations);
    return { sanitized, violations };
  }

  _processData(data, violations) {
    if (typeof data === 'string') {
      return this._scanText(data, violations);
    } else if (Array.isArray(data)) {
      return data.map(item => this._processData(item, violations));
    } else if (data && typeof data === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(data)) {
        out[k] = this._processData(v, violations);
      }
      return out;
    }
    return data;
  }

  _scanText(text, violations) {
    if (!text || text.length < 16) return text;
    let current = text;

    // 1. Regex pattern matching
    for (const [name, regex] of Object.entries(this.patterns)) {
      const matches = current.match(regex);
      if (matches) {
        for (const m of matches) {
          violations.push(new ViolationRecord(
            `secret_detected_${name.toLowerCase()}`,
            RiskLevel.CRITICAL,
            `Exposed secret (${name}) detected in outbound tool output.`
          ));
        }
        current = current.replace(regex, `[REDACTED_SECRET:${name}]`);
      }
    }

    // 2. Base64 decoded secret inspection
    const b64Matches = current.match(this.base64Pattern);
    if (b64Matches) {
      for (const rawB64 of b64Matches) {
        try {
          const decoded = Buffer.from(rawB64, 'base64').toString('utf-8');
          if (decoded.length >= 16) {
            for (const [name, regex] of Object.entries(this.patterns)) {
              if (regex.test(decoded)) {
                violations.push(new ViolationRecord(
                  `secret_detected_base64_${name.toLowerCase()}`,
                  RiskLevel.CRITICAL,
                  `Base64-encoded secret (${name}) detected in tool output.`
                ));
                current = current.replace(rawB64, `[REDACTED_SECRET:BASE64_${name}]`);
                break;
              }
            }
          }
        } catch (e) {}
      }
    }

    // 3. Shannon entropy detection
    const tokens = current.match(this.entropyTokenPattern);
    if (tokens) {
      for (const tok of tokens) {
        if (tok.startsWith('[REDACTED_')) continue;
        const h = this.calculateShannonEntropy(tok);
        if (h >= this.entropyThreshold) {
          violations.push(new ViolationRecord(
            'secret_detected_high_entropy',
            RiskLevel.HIGH,
            `High-entropy token (entropy: ${h.toFixed(2)}) detected in output.`
          ));
          current = current.replace(tok, '[REDACTED_SECRET:HIGH_ENTROPY]');
        }
      }
    }

    return current;
  }
}

module.exports = { SecretScanner };
