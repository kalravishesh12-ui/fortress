"""
PII Redaction Engine (SSN, Credit Cards, Emails, Phones).
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Tuple
from fortress.config import OutboundGuardConfig
from fortress.core.models import RiskLevel, ViolationRecord


class PIIRedactor:
    """
    High-performance PII masking engine with Luhn checksum validation.
    """

    PII_PATTERNS: Dict[str, re.Pattern] = {
        "ssn": re.compile(r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b'),
        "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        "phone": re.compile(r'(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b'),
        "credit_card": re.compile(r'\b[2-6](?:[ -]*?\d){12,18}\b'),
    }

    VALID_CC_PREFIXES = ('2', '3', '4', '5', '6')

    def __init__(self, config: OutboundGuardConfig):
        self.config = config

    def luhn_check(self, card_num: str) -> bool:
        # Fast character extraction without re.sub allocation
        digits = [ord(c) - 48 for c in card_num if '0' <= c <= '9']
        n = len(digits)
        if n < 13 or n > 19:
            return False
        if str(digits[0]) not in self.VALID_CC_PREFIXES:
            return False
        checksum = 0
        parity = n % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                doubled = d * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += d
        return checksum % 10 == 0

    def redact(self, data: Any) -> Tuple[Any, List[ViolationRecord]]:
        if not self.config.mask_pii:
            return data, []

        violations: List[ViolationRecord] = []
        sanitized = self._process_data(data, violations)
        return sanitized, violations

    def _process_data(self, data: Any, violations: List[ViolationRecord], depth: int = 0, max_depth: int = 20) -> Any:
        if depth > max_depth:
            return data
        if isinstance(data, str):
            return self._mask_text(data, violations)
        elif isinstance(data, dict):
            return {k: self._process_data(v, violations, depth + 1, max_depth) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._process_data(item, violations, depth + 1, max_depth) for item in data]
        return data

    def _mask_text(self, text: str, violations: List[ViolationRecord]) -> str:
        if not text or len(text) < 5:
            return text

        has_digits = any('0' <= c <= '9' for c in text)
        has_at = '@' in text

        # Fast exit if text contains neither digits nor '@'
        if not has_digits and not has_at:
            return text

        current_text = text

        # 1. Credit Card (check before phone/ssn to avoid partial collisions)
        if has_digits and "credit_card" in self.config.pii_types:
            for match in self.PII_PATTERNS["credit_card"].finditer(current_text):
                candidate = match.group(0)
                first_digit = next((c for c in candidate if '0' <= c <= '9'), None)
                if first_digit not in self.VALID_CC_PREFIXES:
                    continue
                if self.luhn_check(candidate):
                    violations.append(
                        ViolationRecord(
                            rule_name="pii_detected_credit_card",
                            risk_level=RiskLevel.HIGH,
                            reason="Valid payment card number (Luhn confirmed) detected in tool response.",
                        )
                    )
                    current_text = current_text.replace(candidate, "[REDACTED_PII:CREDIT_CARD]")

        # 2. SSN
        if has_digits and "ssn" in self.config.pii_types:
            found_ssn = False
            for match in self.PII_PATTERNS["ssn"].finditer(current_text):
                matched_str = match.group(0)
                if "[REDACTED_" not in matched_str:
                    found_ssn = True
                    violations.append(
                        ViolationRecord(
                            rule_name="pii_detected_ssn",
                            risk_level=RiskLevel.HIGH,
                            reason="Social Security Number (SSN) detected in tool response.",
                        )
                    )
            if found_ssn:
                current_text = self.PII_PATTERNS["ssn"].sub("[REDACTED_PII:SSN]", current_text)

        # 3. Email
        if has_at and "email" in self.config.pii_types:
            found_email = False
            for match in self.PII_PATTERNS["email"].finditer(current_text):
                found_email = True
                violations.append(
                    ViolationRecord(
                        rule_name="pii_detected_email",
                        risk_level=RiskLevel.MEDIUM,
                        reason="Email address detected in tool response.",
                    )
                )
            if found_email:
                current_text = self.PII_PATTERNS["email"].sub("[REDACTED_PII:EMAIL]", current_text)

        # 4. Phone
        if has_digits and "phone" in self.config.pii_types:
            found_phone = False
            for match in self.PII_PATTERNS["phone"].finditer(current_text):
                matched_str = match.group(0)
                if not (matched_str.startswith("202") or matched_str.startswith("199")) and "[REDACTED_" not in matched_str:
                    found_phone = True
                    violations.append(
                        ViolationRecord(
                            rule_name="pii_detected_phone",
                            risk_level=RiskLevel.MEDIUM,
                            reason="Telephone number detected in tool response.",
                        )
                    )
            if found_phone:
                current_text = self.PII_PATTERNS["phone"].sub("[REDACTED_PII:PHONE]", current_text)

        return current_text
