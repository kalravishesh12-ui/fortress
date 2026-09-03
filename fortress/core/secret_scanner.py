"""
Outbound Secret & Credential Scanner (Regex + Shannon Entropy).
"""

from __future__ import annotations
import base64
import math
import re
from typing import Any, Dict, List, Tuple
from fortress.config import OutboundGuardConfig
from fortress.core.models import RiskLevel, ViolationRecord


class SecretScanner:
    """
    Detects API keys, private keys, bearer tokens, and high-entropy secrets at wire-speed.
    """

    PATTERNS: Dict[str, re.Pattern] = {
        "AWS_ACCESS_KEY": re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        "AWS_SECRET_KEY": re.compile(r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9\/+=]{40})["\']?'),
        "GITHUB_TOKEN": re.compile(r'\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b|\b(github_pat_[A-Za-z0-9_]{82})\b'),
        "OPENAI_API_KEY": re.compile(r'\b(sk-[a-zA-Z0-9_-]{32,}|sk-proj-[a-zA-Z0-9_-]{32,})\b'),
        "ANTHROPIC_API_KEY": re.compile(r'\b(sk-ant-[a-zA-Z0-9_-]{32,})\b'),
        "SLACK_TOKEN": re.compile(r'\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b'),
        "GOOGLE_API_KEY": re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b'),
        "PRIVATE_KEY": re.compile(r'-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP)? PRIVATE KEY[^-]*-----', re.MULTILINE),
        "JWT_TOKEN": re.compile(r'\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)\b'),
        "BEARER_AUTH": re.compile(r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{25,})'),
        "STRIPE_KEY": re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
        "HUGGINGFACE_TOKEN": re.compile(r'\b(hf_[a-zA-Z0-9]{34,})\b'),
    }
    BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})')

    STRIP_CHARS = " \'\",;:.()[]{}"

    def __init__(self, config: OutboundGuardConfig):
        self.config = config

    def calculate_shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def scan_and_redact(self, data: Any) -> Tuple[Any, List[ViolationRecord]]:
        if not self.config.scan_secrets:
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

        # 1. Deterministic Pattern Matching
        for sec_type, pattern in self.PATTERNS.items():
            matches = list(pattern.finditer(current_text))
            if matches:
                for match in matches:
                    matched_str = match.group(0)
                    violations.append(
                        ViolationRecord(
                            rule_name=f"secret_detected_{sec_type.lower()}",
                            risk_level=RiskLevel.CRITICAL,
                            reason=f"Exposed secret ({sec_type}) detected in outbound tool output.",
                            details={"secret_type": sec_type, "length": len(matched_str)},
                        )
                    )
                current_text = pattern.sub(f"[REDACTED_SECRET:{sec_type}]", current_text)

        # 2. Base64-encoded Secret Normalization & Inspection
        b64_matches = list(self.BASE64_PATTERN.finditer(current_text))
        for b64_match in b64_matches:
            raw_b64 = b64_match.group(0)
            try:
                decoded_bytes = base64.b64decode(raw_b64, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) >= 16:
                    for name, pat in self.PATTERNS.items():
                        if pat.search(decoded_str):
                            violations.append(
                                ViolationRecord(
                                    rule_name=f"secret_detected_base64_{name.lower()}",
                                    risk_level=RiskLevel.CRITICAL,
                                    reason=f"Base64-encoded secret ({name}) detected in tool output.",
                                    details={"pattern": name, "b64_snippet": raw_b64[:24]},
                                )
                            )
                            current_text = current_text.replace(raw_b64, f"[REDACTED_SECRET:BASE64_{name}]")
                            break
            except Exception:
                pass

        # 3. Shannon Entropy Scanner for unstructured high-entropy tokens
        tokens = re.findall(r'\S{20,}', current_text)
        for raw_tok in tokens:
            token = raw_tok.strip(self.STRIP_CHARS)
            if token.startswith("[REDACTED_") or len(token) < self.config.min_entropy_length:
                continue
            entropy = self.calculate_shannon_entropy(token)
            if entropy >= self.config.entropy_threshold:
                violations.append(
                    ViolationRecord(
                        rule_name="secret_detected_high_entropy",
                        risk_level=RiskLevel.HIGH,
                        reason=f"High-entropy token (entropy: {entropy:.2f}) detected in output.",
                        details={"entropy": round(entropy, 2), "length": len(token)},
                    )
                )
                current_text = current_text.replace(token, "[REDACTED_SECRET:HIGH_ENTROPY]")

        return current_text
