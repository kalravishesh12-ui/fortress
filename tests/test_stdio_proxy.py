"""
Integration Tests for stdio Transparent Proxy.
"""

import asyncio
import json
import sys
import pytest
from fortress.config import load_policy
from fortress.transport.stdio import StdioProxy


def test_stdio_proxy_initialization():
    policy = load_policy("fortress-policy.yaml")
    proxy = StdioProxy(command=["python", "-c", "print('mock server')"], policy=policy)
    assert proxy.engine is not None
    assert proxy.context.role == "developer"
    assert len(proxy.command) == 3
