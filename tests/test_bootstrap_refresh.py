# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for v0.3.0 per-CPL bucket-fill bootstrap.

The original Kademlia paper (Maymounkov & Mazieres 2002) defines the
join procedure as: insert known node, lookup own ID, then refresh all
k-buckets farther than the closest-neighbor bucket. rust-libp2p does
this synchronously inside the bootstrap QueryId. kademlite v0.2.0 only
ran the self-lookup on bootstrap and deferred per-bucket refresh to
the 5-minute maintenance loop, so cold consumers issuing PUT/GET right
after start saw an under-populated routing table.

v0.3.0 adds:
- ``DhtNode.start(wait_until_routable=True)`` (default) runs one round
  of ``_refresh_buckets`` after the self-lookup.
- ``DhtNode.wait_until_routable()`` for callers who used
  ``start(wait_until_routable=False)`` and want to refresh later.
"""

from unittest.mock import patch

import pytest  # noqa: F401

from kademlite.crypto import _base58btc_encode
from kademlite.dht import DhtNode


def _node_multiaddr(node: DhtNode) -> str:
    host, port = node.listen_addr
    return f"/ip4/{host}/tcp/{port}/p2p/{_base58btc_encode(node.peer_id)}"


async def test_start_default_runs_refresh_buckets() -> None:
    """start() with default wait_until_routable=True must call
    _refresh_buckets exactly once after the bootstrap-time self-lookup,
    so the cold consumer sees distant-bucket peers immediately."""
    node_a = DhtNode()
    await node_a.start("127.0.0.1", 0, wait_until_routable=False)
    addr_a = _node_multiaddr(node_a)
    try:
        node_b = DhtNode()
        # Patch _refresh_buckets to count invocations triggered by start().
        refresh_calls = []
        original_refresh = node_b._refresh_buckets

        async def counting_refresh():
            refresh_calls.append(1)
            await original_refresh()

        with patch.object(node_b, "_refresh_buckets", side_effect=counting_refresh):
            await node_b.start("127.0.0.1", 0, bootstrap_peers=[addr_a])

        try:
            assert len(refresh_calls) == 1, (
                f"expected exactly one _refresh_buckets call from start() "
                f"with default wait_until_routable=True, got {len(refresh_calls)}"
            )
        finally:
            await node_b.stop()
    finally:
        await node_a.stop()


async def test_start_opt_out_skips_refresh_buckets() -> None:
    """start(wait_until_routable=False) must NOT fire _refresh_buckets
    during bootstrap. The maintenance loop retains its own periodic
    refresh, but bootstrap-time is skipped."""
    node_a = DhtNode()
    await node_a.start("127.0.0.1", 0, wait_until_routable=False)
    addr_a = _node_multiaddr(node_a)
    try:
        node_b = DhtNode()
        refresh_calls = []
        original_refresh = node_b._refresh_buckets

        async def counting_refresh():
            refresh_calls.append(1)
            await original_refresh()

        with patch.object(node_b, "_refresh_buckets", side_effect=counting_refresh):
            await node_b.start(
                "127.0.0.1", 0,
                bootstrap_peers=[addr_a],
                wait_until_routable=False,
            )

        try:
            assert len(refresh_calls) == 0, (
                f"_refresh_buckets must not be called from start() when "
                f"wait_until_routable=False; got {len(refresh_calls)} calls"
            )
        finally:
            await node_b.stop()
    finally:
        await node_a.stop()


async def test_wait_until_routable_method_runs_refresh() -> None:
    """DhtNode.wait_until_routable() must invoke _refresh_buckets when
    the routing table is non-empty. Caller-driven equivalent of the
    sync bootstrap-finalization for opted-out start() callers."""
    node_a = DhtNode()
    await node_a.start("127.0.0.1", 0, wait_until_routable=False)
    addr_a = _node_multiaddr(node_a)
    try:
        node_b = DhtNode()
        await node_b.start(
            "127.0.0.1", 0,
            bootstrap_peers=[addr_a],
            wait_until_routable=False,
        )
        try:
            refresh_calls = []
            original_refresh = node_b._refresh_buckets

            async def counting_refresh():
                refresh_calls.append(1)
                await original_refresh()

            with patch.object(node_b, "_refresh_buckets", side_effect=counting_refresh):
                await node_b.wait_until_routable()

            assert len(refresh_calls) == 1
        finally:
            await node_b.stop()
    finally:
        await node_a.stop()


async def test_wait_until_routable_skips_on_empty_routing_table() -> None:
    """If the routing table is empty (e.g. no bootstrap peers configured),
    wait_until_routable() is a no-op; refreshing nothing avoids a
    needless busy loop in _refresh_buckets's bucket scan."""
    node = DhtNode()
    await node.start("127.0.0.1", 0, wait_until_routable=False)
    try:
        refresh_calls = []
        original_refresh = node._refresh_buckets

        async def counting_refresh():
            refresh_calls.append(1)
            await original_refresh()

        with patch.object(node, "_refresh_buckets", side_effect=counting_refresh):
            await node.wait_until_routable()

        assert len(refresh_calls) == 0, (
            f"wait_until_routable() on empty routing table must skip; "
            f"got {len(refresh_calls)} calls"
        )
    finally:
        await node.stop()


async def test_no_bootstrap_skips_refresh_even_with_default() -> None:
    """A node with no bootstrap configured (mDNS-only or fully isolated)
    has nothing to refresh against. start(wait_until_routable=True) must
    skip the refresh in this case rather than spinning on an empty table."""
    node = DhtNode()
    refresh_calls = []
    original_refresh = node._refresh_buckets

    async def counting_refresh():
        refresh_calls.append(1)
        await original_refresh()

    with patch.object(node, "_refresh_buckets", side_effect=counting_refresh):
        # No bootstrap_peers, no bootstrap_dns, no bootstrap_slurm.
        # mDNS may auto-enable but doesn't populate the routing table
        # synchronously during start.
        await node.start("127.0.0.1", 0, enable_mdns=False)

    try:
        assert len(refresh_calls) == 0, (
            f"start() with no bootstrap should skip refresh; "
            f"got {len(refresh_calls)} calls"
        )
    finally:
        await node.stop()
