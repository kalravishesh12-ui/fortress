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
        "credit_card": re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
    }

    def __init__(self, config: OutboundGuardConfig):
        self.config = config

    def luhn_check(self, card_num: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', card_num)]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            if i % 2 == 1:
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

    def _process_data(self, data: Any, violations: List[ViolationRecord]) -> Any:
        if isinstance(data, str):
            return self._mask_text(data, violations)
        elif isinstance(data, dict):
            return {k: self._process_data(v, violations) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._process_data(item, violations) for item in data]
        return data

    def _mask_text(self, text: str, violations: List[ViolationRecord]) -> str:
        current_text = text

        # 1. Credit Card (check before phone/ssn to avoid partial collisions)
        if "credit_card" in self.config.pii_types:
            for match in list(self.PII_PATTERNS["credit_card"].finditer(current_text)):
                candidate = match.group(0)
                clean_digits = re.sub(r'\D', '', candidate)
                if self.luhn_check(clean_digits):
                    violations.append(
                        ViolationRecord(
                            rule_name="pii_detected_credit_card",
                            risk_level=RiskLevel.HIGH,
                            reason="Valid payment card number (Luhn confirmed) detected in tool response.",
                        )
                    )
                    current_text = current_text.replace(candidate, "[REDACTED_PII:CREDIT_CARD]")

        # 2. SSN
        if "ssn" in self.config.pii_types:
            matches = list(self.PII_PATTERNS["ssn"].finditer(current_text))
            if matches:
                for match in matches:
                    matched_str = match.group(0)
                    if "[REDACTED_" not in matched_str:
                        violations.append(
                            ViolationRecord(
                                rule_name="pii_detected_ssn",
                                risk_level=RiskLevel.HIGH,
                                reason="Social Security Number (SSN) detected in tool response.",
                            )
                        )
                current_text = self.PII_PATTERNS["ssn"].sub("[REDACTED_PII:SSN]", current_text)

        # 3. Email
        if "email" in self.config.pii_types:
            matches = list(self.PII_PATTERNS["email"].finditer(current_text))
            if matches:
                for match in matches:
                    violations.append(
                        ViolationRecord(
                            rule_name="pii_detected_email",
                            risk_level=RiskLevel.MEDIUM,
                            reason="Email address detected in tool response.",
                        )
                    )
                current_text = self.PII_PATTERNS["email"].sub("[REDACTED_PII:EMAIL]", current_text)

        # 4. Phone
        if "phone" in self.config.pii_types:
            matches = list(self.PII_PATTERNS["phone"].finditer(current_text))
            if matches:
                for match in matches:
                    matched_str = match.group(0)
                    if not (matched_str.startswith("202") or matched_str.startswith("199")) and "[REDACTED_" not in matched_str:
                        violations.append(
                            ViolationRecord(
                                rule_name="pii_detected_phone",
                                risk_level=RiskLevel.MEDIUM,
                                reason="Telephone number detected in tool response.",
                            )
                        )
                current_text = self.PII_PATTERNS["phone"].sub("[REDACTED_PII:PHONE]", current_text)

        return current_text
