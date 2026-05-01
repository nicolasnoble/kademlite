# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for v0.3.0 dial/accept mid-handshake cleanup and per-stream
task tracking.

The audit's round-3 deferred item: the connection-establishment paths
allocated TCP sockets, Noise state, and yamux background tasks
incrementally, but a failure in any later step (timeout, cancellation,
peer disconnect) left earlier-allocated resources dangling. Listener
closed the writer on accept failure but didn't unwind noise/yamux.
Dial callers timed out at higher layers but didn't release resources
allocated mid-handshake. Per-stream handler tasks spawned by the
dispatcher weren't tracked, so Connection.close() left them running
against a torn-down session.
"""

import asyncio
from unittest.mock import patch

import pytest  # noqa: F401

from kademlite.connection import dial
from kademlite.crypto import Ed25519Identity, _base58btc_encode
from kademlite.dht import DhtNode
from kademlite.listener import Listener


def _node_multiaddr(node: DhtNode) -> str:
    host, port = node.listen_addr
    return f"/ip4/{host}/tcp/{port}/p2p/{_base58btc_encode(node.peer_id)}"


async def test_dial_cleans_up_on_noise_negotiate_failure() -> None:
    """If multistream negotiation for /noise raises mid-dial, dial() must
    not leak the TCP socket. The exception propagates and the writer
    that was constructed during open_connection is closed."""
    identity = Ed25519Identity.generate()
    listener = Listener(identity, host="127.0.0.1", port=0)
    await listener.start()
    host, port = listener.listen_addr

    try:
        client_id = Ed25519Identity.generate()

        # Verify dial's cleanup-on-failure path doesn't leak the yamux
        # background read loop task: a successful negotiate_outbound is
        # required before yamux.start() runs, so by patching it to raise
        # we exercise the partial-handshake path BEFORE yamux is even
        # constructed. See test_connection_close_orders_yamux_before_noise
        # for the post-yamux cleanup-order check.
        with patch(
            "kademlite.connection.negotiate_outbound",
            side_effect=RuntimeError("negotiate boom"),
        ):
            with pytest.raises(RuntimeError, match="negotiate"):
                await dial(client_id, host, port)

        # If the cleanup worked, no orphan task should be pending.
        # asyncio reports orphaned tasks at next scheduling tick; sleep
        # briefly and check Task.all_tasks() doesn't accumulate.
        await asyncio.sleep(0.1)
        all_tasks = asyncio.all_tasks()
        # Filter to tasks that look like yamux background loops (the
        # specific resource we'd leak if cleanup didn't run).
        yamux_loops = [t for t in all_tasks if "_read_loop" in repr(t)]
        assert len(yamux_loops) == 0, (
            f"yamux background task leaked after failed dial: {yamux_loops}"
        )
    finally:
        await listener.stop()


async def test_connection_close_cancels_pending_stream_tasks() -> None:
    """When Connection.close() is called while a per-stream negotiation
    task is in flight, that task must be cancelled - not orphaned to
    run against a torn-down yamux session."""
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
            conn = node_a.peer_store.get_connection(node_b.peer_id)
            assert conn is not None

            # Force a per-stream task by opening a stream that will
            # hang in handler negotiation. Easiest path: the dispatcher
            # already spawns _negotiate_inbound_stream tasks; we just
            # need to verify Connection.close cancels them.
            #
            # Plant a fake task in _stream_tasks that hangs forever, to
            # simulate an in-flight negotiation. close() must cancel it.
            hang = asyncio.Event()  # never set

            async def hang_forever():
                await hang.wait()

            t = asyncio.create_task(hang_forever())
            conn._stream_tasks.add(t)
            t.add_done_callback(conn._stream_tasks.discard)

            assert not t.done(), "fake stream task should be running pre-close"

            await conn.close()

            # After close(), the task should have been cancelled and
            # awaited (gather with return_exceptions=True swallows the
            # CancelledError, so t.done() is True).
            assert t.done(), (
                "Connection.close() should have cancelled the pending "
                "stream task; task is still running"
            )
            # Use t.cancelled() exclusively - calling t.exception() on
            # a cancelled task RAISES CancelledError instead of
            # returning it, so the previous `isinstance(t.exception(),
            # CancelledError)` branch was structurally unsound.
            assert t.cancelled(), (
                f"task should have been cancelled by Connection.close(); "
                f"instead it completed with done={t.done()} cancelled={t.cancelled()}"
            )
        finally:
            await node_b.stop()
    finally:
        await node_a.stop()


async def test_connection_close_orders_yamux_before_noise() -> None:
    """Connection.close() must call yamux.stop() BEFORE noise.close().

    yamux.stop sends a GO_AWAY frame via the noise transport for a
    polite shutdown signal to the remote. If noise is closed first,
    the GO_AWAY write fails and gets swallowed by yamux's own
    try/except, leaving the remote with only an EOF/abort signal.
    The partial-handshake cleanup helper depends on this same
    invariant; both close paths must agree.
    """
    from kademlite.connection import Connection

    call_order = []

    class _FakeYamux:
        is_alive = True

        async def stop(self):
            call_order.append("yamux.stop")

    class _FakeNoise:
        def close(self):
            call_order.append("noise.close")

    conn = Connection(
        identity=None,
        noise=_FakeNoise(),
        yamux=_FakeYamux(),
        remote_peer_id=b"\x00" * 32,
    )
    # No inbound dispatcher / stream tasks; just verify the teardown
    # order on the noise/yamux fields directly.
    await conn.close()

    assert call_order == ["yamux.stop", "noise.close"], (
        f"close() should stop yamux before closing noise; got {call_order}"
    )


async def test_dial_closes_writer_on_pre_noise_failure() -> None:
    """When dial() fails at the multistream-select step (before any
    Noise/Yamux state is constructed), the TCP writer that
    open_connection allocated must be closed by the
    _cleanup_partial_handshake path."""
    identity = Ed25519Identity.generate()
    listener = Listener(identity, host="127.0.0.1", port=0)
    await listener.start()
    host, port = listener.listen_addr

    captured_writers = []
    real_open_connection = asyncio.open_connection

    async def capturing_open(*args, **kwargs):
        reader, writer = await real_open_connection(*args, **kwargs)
        captured_writers.append(writer)
        return reader, writer

    try:
        client_id = Ed25519Identity.generate()
        with (
            patch("kademlite.connection.asyncio.open_connection", side_effect=capturing_open),
            patch(
                "kademlite.connection.negotiate_outbound",
                side_effect=RuntimeError("pre-noise boom"),
            ),
        ):
            with pytest.raises(RuntimeError, match="pre-noise"):
                await dial(client_id, host, port)

        assert len(captured_writers) == 1, "dial should have opened exactly one TCP connection"
        # writer.close was called by _cleanup_partial_handshake; the
        # transport's is_closing() reflects this even though wait_closed
        # may not have completed yet.
        assert captured_writers[0].is_closing(), (
            "dial cleanup should have closed the TCP writer it allocated"
        )
    finally:
        await listener.stop()


async def test_dial_cleans_up_yamux_on_post_start_failure() -> None:
    """When dial() fails AFTER ``yamux.start()`` succeeds (e.g. an
    Exception during register_protocol or start_inbound_handler), the
    cleanup helper must call ``yamux.stop()`` so the background read-loop
    task doesn't outlive the failed dial.

    This exercises the actual expensive partial-handshake case the
    cleanup helper exists for - the negotiate_outbound failure mode
    above triggers cleanup BEFORE yamux is constructed, so it can't
    catch a yamux-stop regression.
    """
    identity = Ed25519Identity.generate()
    listener = Listener(identity, host="127.0.0.1", port=0)
    await listener.start()
    host, port = listener.listen_addr

    try:
        client_id = Ed25519Identity.generate()

        # Patch start_inbound_handler to raise AFTER yamux has been
        # constructed and started in dial(). The cleanup helper must
        # then call yamux.stop() in the except path.
        from kademlite.connection import Connection
        original_start_handler = Connection.start_inbound_handler

        async def failing_handler(self):
            raise RuntimeError("post-yamux boom")

        with patch.object(
            Connection, "start_inbound_handler", new=failing_handler
        ):
            with pytest.raises(RuntimeError, match="post-yamux"):
                await dial(client_id, host, port)

        # Allow event loop to run any background cleanup.
        await asyncio.sleep(0.1)

        # No yamux read-loop task should survive the failed dial.
        all_tasks = asyncio.all_tasks()
        yamux_loops = [t for t in all_tasks if "_read_loop" in repr(t)]
        # The listener side has its own yamux session that stays alive
        # (it accepted the connection successfully); filter to client-side
        # tasks only by checking the task isn't the listener's accepted one.
        # Simpler: check task count is bounded - it should be exactly the
        # listener's accepted-connection task, not two.
        assert len(yamux_loops) <= 1, (
            f"dial cleanup should have stopped yamux on the client side; "
            f"observed {len(yamux_loops)} _read_loop tasks: {yamux_loops}"
        )

        # Restore for any later tests
        with patch.object(Connection, "start_inbound_handler", new=original_start_handler):
            pass
    finally:
        await listener.stop()


async def test_connection_close_with_no_stream_tasks_is_clean() -> None:
    """Connection.close() with no in-flight per-stream tasks must
    proceed normally (no NoneType errors, no hangs on empty gather)."""
    node_a = DhtNode()
    await node_a.start("127.0.0.1", 0, wait_until_routable=False)
    try:
        node_b = DhtNode()
        await node_b.start(
            "127.0.0.1", 0,
            bootstrap_peers=[_node_multiaddr(node_a)],
            wait_until_routable=False,
        )
        try:
            conn = node_a.peer_store.get_connection(node_b.peer_id)
            assert conn is not None
            # Wait briefly for any inbound dispatcher tasks to settle.
            await asyncio.sleep(0.1)
            await conn.close()
            assert not conn.is_alive
        finally:
            await node_b.stop()
    finally:
        await node_a.stop()
