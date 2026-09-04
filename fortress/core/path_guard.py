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
        "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    }

    def __init__(self, config: PathGuardConfig):
        self.config = config
        self._norm_blocked_paths = [p.lower().replace("\\", "/") for p in self.config.blocked_paths]
        self._abs_allowed_bases = [os.path.abspath(b) for b in self.config.allowed_base_directories]

    def _walk_strings(self, data: Any, max_depth: int = 10, max_strings: int = 1000):
        stack = [(data, 0)]
        count = 0
        while stack and count < max_strings:
            curr, depth = stack.pop()
            if depth > max_depth:
                continue
            if isinstance(curr, str):
                count += 1
                yield curr
            elif isinstance(curr, dict):
                for v in curr.values():
                    stack.append((v, depth + 1))
            elif isinstance(curr, (list, tuple)):
                for item in curr:
                    stack.append((item, depth + 1))

    def _extract_strings(self, data: Any, max_depth: int = 10, max_strings: int = 1000) -> List[str]:
        return list(self._walk_strings(data, max_depth, max_strings))

    def inspect_arguments(self, arguments: Any) -> List[ViolationRecord]:
        if not self.config.enabled:
            return []

        violations: List[ViolationRecord] = []
        for val in self._walk_strings(arguments):
            violation = self._check_string_for_path_risks(val)
            if violation:
                violations.append(violation)

        return violations

    def _check_string_for_path_risks(self, raw_str: str) -> Optional[ViolationRecord]:
        raw_clean = raw_str.strip()
        # Skip pure URLs - let SSRF guard inspect them
        if raw_clean.lower().startswith(("http://", "https://", "ftp://", "ws://", "wss://", "grpc://")):
            return None

        # 1. Fast URL-decode pre-check: only unquote if '%' is present
        if "%" in raw_str:
            decoded = urllib.parse.unquote(raw_str)
            double_decoded = urllib.parse.unquote(decoded) if "%" in decoded else decoded
        else:
            decoded = raw_str
            double_decoded = raw_str

        # 2. Check for null byte injections
        if "\x00" in raw_str or "\x00" in decoded or "%00" in raw_str.lower():
            return ViolationRecord(
                rule_name="path_null_byte_injection",
                risk_level=RiskLevel.CRITICAL,
                reason="Null byte injection detected in path argument.",
                details={"input": raw_str},
            )

        # 3. Fast traversal check (only loop if '..' or '%2e' is detected)
        has_dotdot = ".." in raw_str or ".." in decoded or "%2e" in raw_str.lower()
        if has_dotdot:
            for token in self.config.block_traversal_patterns:
                if token in raw_str or token in decoded or token in double_decoded:
                    return ViolationRecord(
                        rule_name="path_traversal_detected",
                        risk_level=RiskLevel.CRITICAL,
                        reason=f"Path traversal sequence '{token}' detected in tool argument.",
                        details={"input": raw_str, "token": token},
                    )

        # 4. Check for Windows DOS reserved device names (handling prefixes, extensions, ADS, and trailing dots)
        clean_path = raw_clean
        if clean_path.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
            clean_path = clean_path[4:]

        norm_for_device = clean_path.replace("\\", "/")
        raw_basename = os.path.basename(norm_for_device)
        ads_stripped = raw_basename.split(":")[0]
        device_candidate = re.sub(r'[\s.]+$', '', ads_stripped).upper()
        prefix_before_ext = device_candidate.split(".")[0].strip()

        is_reserved = False
        reserved_match = None
        if device_candidate in self.WINDOWS_RESERVED:
            is_reserved = True
            reserved_match = device_candidate
        elif prefix_before_ext in self.WINDOWS_RESERVED:
            is_reserved = True
            reserved_match = prefix_before_ext
        elif re.match(r'^(?:COM|LPT)[0-9]$', device_candidate):
            is_reserved = True
            reserved_match = device_candidate
        elif re.match(r'^(?:COM|LPT)[0-9]$', prefix_before_ext):
            is_reserved = True
            reserved_match = prefix_before_ext

        if is_reserved:
            return ViolationRecord(
                rule_name="path_reserved_device_blocked",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Target path references Windows reserved system device '{reserved_match}'.",
                details={"input": raw_str, "device": reserved_match},
            )

        # 5. Check for NTFS alternate data streams (e.g. file.txt:stream or file.txt::$DATA)
        clean_norm = clean_path.replace("\\", "/")
        path_without_drive = re.sub(r'^[a-zA-Z]:', '', clean_norm)
        if ":" in path_without_drive:
            return ViolationRecord(
                rule_name="path_alternate_data_stream_blocked",
                risk_level=RiskLevel.CRITICAL,
                reason="NTFS Alternate Data Stream access detected in path argument.",
                details={"input": raw_str},
            )

        # 6. Check for blocked sensitive files / paths using precomputed norms
        normalized_lower = raw_str.lower().replace("\\", "/")
        for blocked, blocked_norm in zip(self.config.blocked_paths, self._norm_blocked_paths):
            if blocked_norm in normalized_lower:
                return ViolationRecord(
                    rule_name="path_sensitive_target_blocked",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Access to sensitive target '{blocked}' is forbidden.",
                    details={"input": raw_str, "blocked_target": blocked},
                )

        # 7. Non-blocking Symlink canonicalization check (avoid slow NFS/remote stat)
        if self._looks_like_file_path(raw_str):
            try:
                if os.path.islink(raw_str):
                    real_target = os.path.realpath(raw_str)
                    real_norm = real_target.lower().replace("\\", "/")
                    for blocked, blocked_norm in zip(self.config.blocked_paths, self._norm_blocked_paths):
                        if blocked_norm in real_norm:
                            return ViolationRecord(
                                rule_name="path_symlink_escape_blocked",
                                risk_level=RiskLevel.CRITICAL,
                                reason=f"Path resolves via symlink to forbidden target '{real_target}'.",
                                details={"symlink": raw_str, "resolved_target": real_target},
                            )
            except (OSError, ValueError):
                pass

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
            for abs_base in self._abs_allowed_bases:
                try:
                    common = os.path.commonpath([abs_base, abs_target])
                    if common == abs_base:
                        return True
                except ValueError:
                    continue
            return False
        except Exception:
            return False
