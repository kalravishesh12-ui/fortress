"""
Indirect Prompt Injection & Jailbreak Detector.
"""

from __future__ import annotations
import re
from typing import Any, List, Tuple
from mcp_shield.config import OutboundGuardConfig
from mcp_shield.core.models import RiskLevel, ViolationRecord


class InjectionDetector:
    """
    Detects indirect prompt injection, instruction overrides, and exfiltration triggers.
    """

    INJECTION_PATTERNS: List[Tuple[str, re.Pattern, RiskLevel]] = [
        (
            "override_instructions",
            re.compile(r'(?i)(?:ignore|disregard|forget|override|cancel)\s+(?:all\s+)?(?:previous|prior|above|system|model|developer|assistant|\s+)*(?:instructions|prompts|rules|commands|directives)'),
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
            re.compile(r'[​-‍﻿⁠‎‏]{3,}'),
            RiskLevel.HIGH,
        ),
        (
            "hidden_developer_mode",
            re.compile(r'(?i)(?:developer mode is now enabled|bypass security filters|security checks disabled)'),
            RiskLevel.HIGH,
        ),
    ]

    def __init__(self, config: OutboundGuardConfig):
        self.config = config

    def inspect(self, data: Any) -> Tuple[Any, List[ViolationRecord]]:
        if not self.config.scan_prompt_injection:
            return data, []

        violations: List[ViolationRecord] = []
        sanitized = self._process_data(data, violations)
        return sanitized, violations

    def _process_data(self, data: Any, violations: List[ViolationRecord]) -> Any:
        if isinstance(data, str):
            return self._scan_text(data, violations)
        elif isinstance(data, dict):
            return {k: self._process_data(v, violations) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._process_data(item, violations) for item in data]
        return data

    def _scan_text(self, text: str, violations: List[ViolationRecord]) -> str:
        current_text = text

        for name, pattern, risk in self.INJECTION_PATTERNS:
            matches = list(pattern.finditer(current_text))
            if matches:
                for match in matches:
                    violations.append(
                        ViolationRecord(
                            rule_name=f"prompt_injection_{name}",
                            risk_level=risk,
                            reason=f"Indirect prompt injection or jailbreak trigger detected ({name}).",
                            details={"matched_snippet": match.group(0)[:80]},
                        )
                    )
                if self.config.injection_action == "sanitize":
                    current_text = pattern.sub("[STRIPPED_SUSPICIOUS_INJECTION_DIRECTIVE]", current_text)

        return current_text
