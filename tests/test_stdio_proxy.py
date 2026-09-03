"""
Integration Tests for stdio Transparent Proxy.
"""

import asyncio
import json
import sys
import pytest
from mcp_shield.config import load_policy
from mcp_shield.transport.stdio import StdioProxy


def test_stdio_proxy_initialization():
    policy = load_policy("mcp-policy.yaml")
    proxy = StdioProxy(command=["python", "-c", "print('mock server')"], policy=policy)
    assert proxy.engine is not None
    assert proxy.context.role == "developer"
    assert len(proxy.command) == 3
