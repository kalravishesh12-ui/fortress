const { RiskLevel, ViolationRecord } = require('./models');

class InjectionDetector {
  constructor() {
    this.patterns = [
      {
        name: 'override_instructions',
        regex: /(?:ignore|disregard|forget|override|cancel)\s+(?:all\s+)?(?:previous|prior|above|system|model|developer|assistant|\s+)*(?:instructions|prompts|rules|commands|directives)/i,
        risk: RiskLevel.CRITICAL,
      },
      {
        name: 'jailbreak_roleplay',
        regex: /(?:you are now|act as|pretend to be)\s+(?:unrestricted|dan|jailbreak|root|system administrator|godmode)/i,
        risk: RiskLevel.CRITICAL,
      },
      {
        name: 'system_delimiter_injection',
        regex: /(?:\[system\s*instruction\]|<\|im_start\|>system|<\|system\|>|<<SYS>>|---BEGIN SYSTEM PROMPT---)/i,
        risk: RiskLevel.CRITICAL,
      },
      {
        name: 'markdown_image_exfiltration',
        regex: /!\[.*?\]\((https?:\/\/[^\s\)]+(?:\?|&)(?:data|leak|token|secret|exfil|c|log)=[^)]+)\)/i,
        risk: RiskLevel.CRITICAL,
      },
      {
        name: 'zero_width_unicode_injection',
        regex: /[\u200B-\u200D\uFEFF]{3,}/,
        risk: RiskLevel.HIGH,
      }
    ];
  }

  inspect(data) {
    const violations = [];
    const sanitized = this._processData(data, violations);
    return { sanitized, violations };
  }

  _scanText(text, violations) {
    let current = text;
    for (const item of this.patterns) {
      if (item.regex.test(current)) {
        violations.push(new ViolationRecord(
          `prompt_injection_${item.name}`,
          item.risk,
          `Indirect prompt injection or jailbreak trigger detected (${item.name}).`
        ));
        current = current.replace(item.regex, '[STRIPPED_SUSPICIOUS_INJECTION_DIRECTIVE]');
      }
    }
    return current;
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
}

module.exports = { InjectionDetector };
