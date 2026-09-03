"""
Egress & Server-Side Request Forgery (SSRF) Protection.
"""

from __future__ import annotations
import ipaddress
import re
import socket
import urllib.parse
from typing import Any, List, Optional
from mcp_shield.config import SSRFGuardConfig
from mcp_shield.core.models import RiskLevel, ViolationRecord


class SSRFGuard:
    """
    Deterministic SSRF Inspector for URLs, hostnames, and IP addresses in tool arguments.
    """

    URL_REGEX = re.compile(r'^(?:[a-zA-Z][a-zA-Z0-9+-.]*):\/\/([^\/\s:]+)(?::(\d+))?(?:[\/?#]|$)', re.IGNORECASE)

    def __init__(self, config: SSRFGuardConfig):
        self.config = config
        self._compiled_networks = []
        for cidr in self.config.blocked_ip_ranges:
            try:
                self._compiled_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def inspect_arguments(self, arguments: Any) -> List[ViolationRecord]:
        if not self.config.enabled:
            return []

        violations: List[ViolationRecord] = []
        string_values = self._extract_strings(arguments)

        for val in string_values:
            violation = self._check_string_for_ssrf(val)
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

    def _check_string_for_ssrf(self, raw_str: str) -> Optional[ViolationRecord]:
        raw_clean = raw_str.strip()

        # 1. Check if string is a URL
        parsed = urllib.parse.urlparse(raw_clean)
        hostname = parsed.hostname

        # If not parsed directly by urlparse, try regex
        if not hostname:
            match = self.URL_REGEX.match(raw_clean)
            if match:
                hostname = match.group(1)

        # If not URL, check if string is raw IP or hostname
        if not hostname:
            if self._looks_like_host_or_ip(raw_clean):
                hostname = raw_clean.split(":")[0].strip("[]")

        if not hostname:
            return None

        hostname_lower = hostname.lower().strip("[]")

        # 2. Blocked Domains check
        for blocked_domain in self.config.blocked_domains:
            if hostname_lower == blocked_domain.lower() or hostname_lower.endswith("." + blocked_domain.lower()):
                return ViolationRecord(
                    rule_name="ssrf_blocked_domain",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Destination domain '{hostname}' matches blocked infrastructure / metadata domain '{blocked_domain}'.",
                    details={"hostname": hostname, "blocked_domain": blocked_domain, "raw": raw_str},
                )

        # 3. Direct IP address check (handles IPv4, IPv6, IPv4-mapped, hex, decimal, octal)
        ip_obj = self._parse_ip_address(hostname_lower)
        if ip_obj:
            # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254)
            if getattr(ip_obj, "ipv4_mapped", None):
                ip_obj = ip_obj.ipv4_mapped
            return self._verify_ip_safety(ip_obj, raw_str)

        # 4. Anti-DNS Rebinding / Localhost string check
        if hostname_lower in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "169.254.169.254"):
            return ViolationRecord(
                rule_name="ssrf_forbidden_host",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Destination host '{hostname}' points directly to private or cloud metadata endpoint.",
                details={"hostname": hostname, "raw": raw_str},
            )

        return None

    def _looks_like_host_or_ip(self, val: str) -> bool:
        if " " in val or len(val) > 255:
            return False
        return bool(re.match(r'^(?:\[?[0-9a-fA-F:]+\]?|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost)(?::\d+)?$', val))

    def _parse_ip_address(self, host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        clean_host = host.strip("[]")
        try:
            return ipaddress.ip_address(clean_host)
        except ValueError:
            pass

        # Check for integer/hex representation of IPv4 (e.g. 2130706433 or 0x7f000001)
        if clean_host.isdigit():
            try:
                num = int(clean_host)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except ValueError:
                pass

        if clean_host.startswith("0x"):
            try:
                num = int(clean_host, 16)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except ValueError:
                pass

        # Check for octal dotted-quad (e.g. 0177.0.0.1)
        parts = clean_host.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            try:
                norm_parts = [str(int(p, 8) if p.startswith("0") and len(p) > 1 else int(p)) for p in parts]
                return ipaddress.IPv4Address(".".join(norm_parts))
            except Exception:
                pass

        return None

    def _verify_ip_safety(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, raw_str: str) -> Optional[ViolationRecord]:
        for net in self._compiled_networks:
            if ip_obj in net:
                return ViolationRecord(
                    rule_name="ssrf_blocked_network_range",
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"Target IP address '{ip_obj}' falls within forbidden network range '{net}' (e.g. private/internal/cloud metadata).",
                    details={"ip": str(ip_obj), "network": str(net), "raw": raw_str},
                )

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return ViolationRecord(
                rule_name="ssrf_private_network_access",
                risk_level=RiskLevel.CRITICAL,
                reason=f"Target IP address '{ip_obj}' is a private/loopback/link-local address.",
                details={"ip": str(ip_obj), "raw": raw_str},
            )

        return None

    def resolve_and_verify(self, hostname: str, port: int = 80) -> Tuple[bool, Optional[str], Optional[ViolationRecord]]:
        """
        Resolves hostname to IP once and validates against private/cloud metadata ranges.
        Neutralizes Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding attacks.
        """
        clean_host = hostname.strip("[]")
        try:
            addr_info = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not addr_info:
                return False, None, ViolationRecord(
                    rule_name="ssrf_dns_resolution_failed",
                    risk_level=RiskLevel.HIGH,
                    reason=f"Could not resolve host '{hostname}'.",
                )
            # Check all resolved addresses
            for family, socktype, proto, canonname, sockaddr in addr_info:
                resolved_ip_str = sockaddr[0]
                ip_obj = ipaddress.ip_address(resolved_ip_str)
                if getattr(ip_obj, "ipv4_mapped", None):
                    ip_obj = ip_obj.ipv4_mapped

                violation = self._verify_ip_safety(ip_obj, f"{hostname} -> {resolved_ip_str}")
                if violation:
                    return False, resolved_ip_str, violation

            primary_ip = addr_info[0][4][0]
            return True, primary_ip, None
        except socket.gaierror as e:
            return False, None, ViolationRecord(
                rule_name="ssrf_dns_resolution_error",
                risk_level=RiskLevel.HIGH,
                reason=f"DNS resolution failed for '{hostname}': {e}",
            )
        except Exception as e:
            return False, None, ViolationRecord(
                rule_name="ssrf_dns_error",
                risk_level=RiskLevel.HIGH,
                reason=f"Error validating DNS resolution for '{hostname}': {e}",
            )

    async def open_pinned_connection(
        self,
        url: str,
        timeout: float = 10.0,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        """
        Establishes an outbound socket connection pinned directly to the pre-validated IP address.
        Eliminates DNS Rebinding TOCTOU attacks at the network socket layer.
        Returns (reader, writer, pinned_ip).
        """
        import asyncio
        import ssl

        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: '{url}' lacks a valid hostname.")

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_safe, pinned_ip, violation = self.resolve_and_verify(parsed.hostname, port)
        if not is_safe or not pinned_ip:
            raise PermissionError(
                f"Blocked by MCP-Shield SSRF Guard: {violation.reason if violation else 'Unsafe destination'}"
            )

        # Build TLS context if HTTPS, validating server certificate against original domain
        ssl_ctx = None
        if parsed.scheme == "https":
            ssl_ctx = ssl.create_default_context()

        # Connect DIRECTLY to pinned IP to neutralize 0-second TTL rebinding
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=pinned_ip,
                port=port,
                ssl=ssl_ctx,
                server_hostname=parsed.hostname if ssl_ctx else None,
            ),
            timeout=timeout,
        )
        return reader, writer, pinned_ip
