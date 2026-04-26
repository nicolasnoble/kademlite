# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Contract tests for the README quick-start example's API surface.

These are signature-level tests, not full end-to-end. They ensure the public
API used in the README docstring still exists with the documented shape,
catching silent README drift when internal refactors land.
"""

import asyncio
import inspect

from kademlite import DhtNode


def test_readme_top_level_import():
    """README: ``from kademlite import DhtNode`` must work."""
    from kademlite import DhtNode as _DhtNode  # noqa: F401  # re-import is the test


def test_dhtnode_constructor_no_required_args():
    """README: ``node = DhtNode()`` must work without arguments."""
    node = DhtNode()
    assert node is not None


def test_dhtnode_start_signature():
    """README uses ``listen_host``, ``listen_port``, ``bootstrap_peers`` kwargs on start()."""
    sig = inspect.signature(DhtNode.start)
    params = sig.parameters
    assert "listen_host" in params
    assert "listen_port" in params
    assert "bootstrap_peers" in params


def test_dhtnode_put_signature():
    """README uses ``put(key, value)`` with bytes args."""
    sig = inspect.signature(DhtNode.put)
    params = sig.parameters
    assert "key" in params
    assert "value" in params


def test_dhtnode_get_signature():
    """README uses ``get(key)`` with bytes arg."""
    sig = inspect.signature(DhtNode.get)
    assert "key" in sig.parameters


def test_dhtnode_stop_exists():
    """README uses ``await node.stop()``."""
    assert hasattr(DhtNode, "stop")
    assert callable(DhtNode.stop)


def test_dhtnode_async_methods():
    """README uses ``await`` on start/put/get/stop, so all must be coroutines."""
    assert asyncio.iscoroutinefunction(DhtNode.start)
    assert asyncio.iscoroutinefunction(DhtNode.put)
    assert asyncio.iscoroutinefunction(DhtNode.get)
    assert asyncio.iscoroutinefunction(DhtNode.stop)
