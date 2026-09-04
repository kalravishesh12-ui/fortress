"""
Indirect Prompt Injection & Jailbreak Detector.
"""

from __future__ import annotations
import re
from typing import Any, List, Tuple
from fortress.config import OutboundGuardConfig
from fortress.core.models import RiskLevel, ViolationRecord


class InjectionDetector:
    """
    Detects indirect prompt injection, instruction overrides, and exfiltration triggers.
    """

    INJECTION_PATTERNS: List[Tuple[str, re.Pattern, RiskLevel]] = [
        (
            "override_instructions",
            re.compile(r'(?i)(?:ignore|disregard|forget|override|cancel)\s+(?:all\s+)?(?:(?:previous|prior|above|system|model|developer|assistant)\s+)*(?:instructions|prompts|rules|commands|directives)'),
            RiskLevel.CRITICAL,
        ),
        (
            "jailbreak_roleplay",
            re.compile(r'(?i)(?:you are now|act as|pretend to be)\s+(?:unrestricted|dan|jailbreak|root|system administrator|godmode|evilbot)'),
            RiskLevel.CRITICAL,
        ),
        (
            "system_delimiter_injection",
            re.compile(r'(?i)(?:\[system\s*instruction\]|<\|im_start\|>system|<\|system\|>|<<SYS>>|---BEGIN SYSTEM PROMPT---)'),
            RiskLevel.CRITICAL,
        ),
        (
            "markdown_image_exfiltration",
            re.compile(r'!\[.*?\]\((https?:\/\/[^\s\)]+(?:\?|&)(?:data|leak|token|secret|exfil|c|log)=[^)]+)\)', re.IGNORECASE),
            RiskLevel.CRITICAL,
        ),
        (
            "zero_width_unicode_injection",
            re.compile(r'[\u200B-\u200D\uFEFF\uFE00-\uFE0F\u2060\u200E\u200F]{3,}'),
            RiskLevel.HIGH,
        ),
        (
            "hidden_developer_mode",
            re.compile(r'(?i)(?:developer mode is now enabled|bypass security filters|security checks disabled)'),
            RiskLevel.HIGH,
        ),
    ]

    # Unified single-pass linear DFA regex for all prompt injection patterns
    COMBINED_INJECTION_PATTERN = re.compile(
        r'(?P<override_instructions>(?i:(?:ignore|disregard|forget|override|cancel)\s+(?:all\s+)?(?:(?:previous|prior|above|system|model|developer|assistant)\s+)*(?:instructions|prompts|rules|commands|directives)))|'
        r'(?P<jailbreak_roleplay>(?i:(?:you are now|act as|pretend to be)\s+(?:unrestricted|dan|jailbreak|root|system administrator|godmode|evilbot)))|'
        r'(?P<system_delimiter_injection>(?i:(?:\[system\s*instruction\]|<\|im_start\|>system|<\|system\|>|<<SYS>>|---BEGIN SYSTEM PROMPT---)))|'
        r'(?P<markdown_image_exfiltration>(?i:!\[.*?\]\((?:https?:\/\/[^\s\)]+(?:\?|&)(?:data|leak|token|secret|exfil|c|log)=[^)]+)\)))|'
        r'(?P<zero_width_unicode_injection>[\u200B-\u200D\uFEFF\uFE00-\uFE0F\u2060\u200E\u200F]{3,})|'
        r'(?P<hidden_developer_mode>(?i:(?:developer mode is now enabled|bypass security filters|security checks disabled)))'
    )

    RISK_MAP = {
        "override_instructions": RiskLevel.CRITICAL,
        "jailbreak_roleplay": RiskLevel.CRITICAL,
        "system_delimiter_injection": RiskLevel.CRITICAL,
        "markdown_image_exfiltration": RiskLevel.CRITICAL,
        "zero_width_unicode_injection": RiskLevel.HIGH,
        "hidden_developer_mode": RiskLevel.HIGH,
    }

    def __init__(self, config: OutboundGuardConfig):
        self.config = config

    def inspect(self, data: Any) -> Tuple[Any, List[ViolationRecord]]:
        if not self.config.scan_prompt_injection:
            return data, []

        violations: List[ViolationRecord] = []
        sanitized = self._process_data(data, violations)
        return sanitized, violations

    def _process_data(self, data: Any, violations: List[ViolationRecord], depth: int = 0, max_depth: int = 20) -> Any:
        if depth > max_depth:
            return data
        if isinstance(data, str):
            return self._scan_text(data, violations)
        elif isinstance(data, dict):
            return {k: self._process_data(v, violations, depth + 1, max_depth) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._process_data(item, violations, depth + 1, max_depth) for item in data]
        return data

    MAX_TEXT_SCAN_LENGTH = 1_000_000

    def _scan_text(self, text: str, violations: List[ViolationRecord]) -> str:
        if not text or len(text) < 5:
            return text

        if len(text) > self.MAX_TEXT_SCAN_LENGTH:
            violations.append(
                ViolationRecord(
                    rule_name="prompt_injection_payload_size_exceeded",
                    risk_level=RiskLevel.MEDIUM,
                    reason=f"Payload length ({len(text)} chars) exceeds maximum prompt injection scan threshold (1MB).",
                    details={"length": len(text), "max_allowed": self.MAX_TEXT_SCAN_LENGTH},
                )
            )
            return text

        if not self.COMBINED_INJECTION_PATTERN.search(text):
            return text

        current_text = text
        for match in self.COMBINED_INJECTION_PATTERN.finditer(current_text):
            name = match.lastgroup
            risk = self.RISK_MAP.get(name, RiskLevel.HIGH)
            violations.append(
                ViolationRecord(
                    rule_name=f"prompt_injection_{name}",
                    risk_level=risk,
                    reason=f"Indirect prompt injection or jailbreak trigger detected ({name}).",
                    details={"matched_snippet": match.group(0)[:80]},
                )
            )

        if self.config.injection_action == "sanitize":
            current_text = self.COMBINED_INJECTION_PATTERN.sub(
                "[STRIPPED_SUSPICIOUS_INJECTION_DIRECTIVE]", current_text
            )

        return current_text
