"""
Path Traversal & Filesystem Sandbox Validator.
"""

from __future__ import annotations
import os
import re
import urllib.parse
from typing import Any, List, Optional
from fortress.config import PathGuardConfig
from fortress.core.models import RiskLevel, ViolationRecord


class PathGuard:
    """
    Deep argument inspector for path traversal, unauthorized directory escapes, and sensitive files.
    """

    WINDOWS_RESERVED = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }

    def __init__(self, config: PathGuardConfig):
        self.config = config

    def inspect_arguments(self, arguments: Any) -> List[ViolationRecord]:
        if not self.config.enabled:
            return []

        violations: List[ViolationRecord] = []
        string_values = self._extract_strings(arguments)

        for val in string_values:
            violation = self._check_string_for_path_risks(val)
            if violation:
                violations.append(violation)

        return violations

    def _extract_strings(self, data: Any) -> List[str]:
        results: List[str] = []
        if isinstance(data, str):
            results.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                results.extend(self._extract_strings(v))
        elif isinstance(data, list):
            for item in data:
                results.extend(self._extract_strings(item))
        return results

    def _check_string_for_path_risks(self, raw_str: str) -> Optional[ViolationRecord]:
        raw_clean = raw_str.strip()
        # Skip pure URLs - let SSRF guard inspect them
        if raw_clean.lower().startswith(("http://", "https://", "ftp://", "ws://", "wss://", "grpc://")):
            return None

        # 1. URL-decode and unquote to prevent obfuscated %2e%2e traversal
        decoded = urllib.parse.unquote(raw_str)
        double_decoded = urllib.parse.unquote(decoded)

        # 2. Check for null byte injections
        if "\x00" in raw_str or "\x00" in decoded or "%00" in raw_str.lower():
            return ViolationRecord(
                rule_name="path_null_byte_injection",
                risk_level=RiskLevel.CRITICAL,
                reason="Null byte injection detected in path argument.",
                details={"input": raw_str},
            )

        # 3. Check for traversal patterns
        for token in self.config.block_traversal_patterns:
            if token in raw_str or token in decoded or token in double_decoded:
                if ".." in raw_str or ".." in decoded or "%2e%2e" in raw_str.lower():
                    return ViolationRecord(
                        rule_name="path_traversal_detected",
                        risk_level=RiskLevel.CRITICAL,
                        reason=f"Path traversal sequence '{token}' detected in tool argument.",
                        details={"input": raw_str, "token": token},
                    )

        # 4. Check for Windows DOS reserved device names
        base_name = os.path.basename(raw_clean.replace("\\", "/")).split(".")[0].upper()
        if base_name in self.WINDOWS_RESERVED:
            return ViolationRecord(
                rule_name="path_reserved_device_blocked",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Target path references Windows reserved system device '{base_name}'.",
                details={"input": raw_str, "device": base_name},
            )

        # 5. Check for NTFS alternate data streams (e.g. file.txt:stream)
        clean_norm = raw_clean.replace("\\", "/")
        # Allow Windows drive letter like C:/, but disallow subsequent colons
        path_without_drive = re.sub(r'^[a-zA-Z]:', '', clean_norm)
        if ":" in path_without_drive:
            return ViolationRecord(
                rule_name="path_alternate_data_stream_blocked",
                risk_level=RiskLevel.CRITICAL,
                reason="NTFS Alternate Data Stream access detected in path argument.",
                details={"input": raw_str},
            )

        # 6. Check for blocked sensitive files / paths
        normalized_lower = raw_str.lower().replace("\\", "/")
        for blocked in self.config.blocked_paths:
            blocked_norm = blocked.lower().replace("\\", "/")
            if blocked_norm in normalized_lower:
                return ViolationRecord(
                    rule_name="path_sensitive_target_blocked",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Access to sensitive target '{blocked}' is forbidden.",
                    details={"input": raw_str, "blocked_target": blocked},
                )

        # 7. Symlink canonicalization check
        if self._looks_like_file_path(raw_str) and (os.path.exists(raw_str) or os.path.islink(raw_str)):
            real_target = os.path.realpath(raw_str)
            for blocked in self.config.blocked_paths:
                blocked_norm = blocked.lower().replace("\\", "/")
                if blocked_norm in real_target.lower().replace("\\", "/"):
                    return ViolationRecord(
                        rule_name="path_symlink_escape_blocked",
                        risk_level=RiskLevel.CRITICAL,
                        reason=f"Path resolves via symlink to forbidden target '{real_target}'.",
                        details={"symlink": raw_str, "resolved_target": real_target},
                    )

        # 8. Sandbox boundary validation if it looks like a local file path
        if self._looks_like_file_path(raw_str) and self.config.allowed_base_directories:
            if not self._is_within_allowed_bases(raw_str):
                return ViolationRecord(
                    rule_name="path_sandbox_escape",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Path '{raw_str}' resolves outside allowed sandbox directories.",
                    details={"input": raw_str, "allowed_bases": self.config.allowed_base_directories},
                )

        return None

    def _looks_like_file_path(self, val: str) -> bool:
        if val.startswith(("http://", "https://", "ftp://")):
            return False
        return "/" in val or "\\" in val or val.endswith((".txt", ".json", ".py", ".md", ".sh", ".yaml", ".yml", ".env", ".key"))

    def _is_within_allowed_bases(self, target_path: str) -> bool:
        try:
            abs_target = os.path.abspath(target_path)
            for base in self.config.allowed_base_directories:
                abs_base = os.path.abspath(base)
                try:
                    common = os.path.commonpath([abs_base, abs_target])
                    if common == abs_base:
                        return True
                except ValueError:
                    continue
            return False
        except Exception:
            return False
