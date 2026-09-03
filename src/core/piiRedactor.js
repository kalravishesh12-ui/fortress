const { RiskLevel, ViolationRecord } = require('./models');

class PIIRedactor {
  constructor() {
    this.ssnPattern = /\b(\d{3}-\d{2}-\d{4})\b/g;
    this.emailPattern = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    this.creditCardPattern = /\b(?:\d[ -]*?){13,19}\b/g;
  }

  luhnCheck(candidate) {
    let clean = '';
    for (let i = 0; i < candidate.length; i++) {
      const code = candidate.charCodeAt(i);
      if (code >= 48 && code <= 57) clean += candidate[i];
    }
    const len = clean.length;
    if (len < 13 || len > 19) return false;
    const first = clean[0];
    if (first !== '2' && first !== '3' && first !== '4' && first !== '5' && first !== '6') return false;

    let sum = 0;
    let shouldDouble = false;
    for (let i = len - 1; i >= 0; i--) {
      let digit = clean.charCodeAt(i) - 48;
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  redact(data) {
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
    let current = text;

    // 1. Credit Cards with Luhn validation
    current = current.replace(this.creditCardPattern, (match) => {
      if (this.luhnCheck(match)) {
        violations.push(new ViolationRecord(
          'pii_detected_credit_card',
          RiskLevel.HIGH,
          'Valid payment card number (Luhn confirmed) detected in tool response.'
        ));
        return '[REDACTED_PII:CREDIT_CARD]';
      }
      return match;
    });

    // 2. SSN
    if (this.ssnPattern.test(current)) {
      violations.push(new ViolationRecord(
        'pii_detected_ssn',
        RiskLevel.HIGH,
        'Social Security Number (SSN) detected in tool response.'
      ));
      current = current.replace(this.ssnPattern, '[REDACTED_PII:SSN]');
    }

    // 3. Email
    if (this.emailPattern.test(current)) {
      violations.push(new ViolationRecord(
        'pii_detected_email',
        RiskLevel.MEDIUM,
        'Email address detected in tool response.'
      ));
      current = current.replace(this.emailPattern, '[REDACTED_PII:EMAIL]');
    }

    return current;
  }
}

module.exports = { PIIRedactor };
