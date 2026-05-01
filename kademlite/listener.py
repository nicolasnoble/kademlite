# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""TCP listener for inbound libp2p connections.

Accepts inbound TCP connections and performs the responder-side handshake:
TCP -> Noise (responder) -> Yamux -> Connection.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable

from .connection import Connection, accept
from .crypto import Ed25519Identity

log = logging.getLogger(__name__)


class Listener:
    """Listens for inbound libp2p connections on a TCP address."""

    # Default max concurrent inbound connections (0 = unlimited)
    DEFAULT_MAX_CONNECTIONS = 256

    # Cap on the responder-side handshake (multistream + Noise + Yamux).
    # A slow or malicious peer that drags out the handshake otherwise
    # holds a max_connections slot indefinitely.
    DEFAULT_HANDSHAKE_TIMEOUT = 10.0

    def __init__(
        self,
        identity: Ed25519Identity,
        host: str = "0.0.0.0",
        port: int = 0,
        supported_protocols: list[str] | None = None,
        on_connection: Callable[[Connection], Awaitable[None]] | None = None,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    ):
        if handshake_timeout <= 0:
            raise ValueError(
                f"handshake_timeout must be positive, got {handshake_timeout}"
            )
        self.identity = identity
        self.host = host
        self.port = port
        self.supported_protocols = supported_protocols
        self.on_connection = on_connection
        self.max_connections = max_connections
        self.handshake_timeout = handshake_timeout
        self._server: asyncio.Server | None = None
        self._listen_addr: tuple[str, int] | None = None
        self._active_connections = 0

    @property
    def listen_addr(self) -> tuple[str, int] | None:
        """The (host, port) this listener is bound to, or None if not started."""
        return self._listen_addr

    async def start(self) -> tuple[str, int]:
        """Start listening. Returns the (host, port) we're bound to."""
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        sock = self._server.sockets[0]
        self._listen_addr = sock.getsockname()[:2]
        log.info(f"listening on {self._listen_addr[0]}:{self._listen_addr[1]}")
        return self._listen_addr

    async def stop(self) -> None:
        """Stop accepting new connections."""
        if self._server:
            self._server.close()
            self._server = None
            self._listen_addr = None

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single inbound TCP connection."""
        remote = writer.get_extra_info("peername")

        if self.max_connections > 0 and self._active_connections >= self.max_connections:
            log.warning(
                f"rejecting connection from {remote}: at limit "
                f"({self._active_connections}/{self.max_connections})"
            )
            writer.close()
            return

        self._active_connections += 1
        accept_succeeded = False
        try:
            conn = await asyncio.wait_for(
                accept(
                    self.identity, reader, writer,
                    supported_protocols=self.supported_protocols,
                ),
                timeout=self.handshake_timeout,
            )
            accept_succeeded = True
            log.info(f"accepted connection from {remote}, peer {conn.remote_peer_id.hex()[:16]}...")
            if self.on_connection:
                await self.on_connection(conn)
        except asyncio.TimeoutError:
            log.warning(
                f"handshake timeout from {remote} after {self.handshake_timeout}s"
            )
        except Exception as e:
            log.warning(f"failed to accept connection from {remote}: {e}")
        finally:
            # Close the writer on every non-success path including
            # external cancellation of _handle_connection itself.
            # asyncio.CancelledError is a BaseException (not Exception)
            # so the previous structure with two except clauses skipped
            # writer.close on cancellation - the writer leaked, which
            # contradicts the listener-owns-writer assumption that
            # Connection.accept() relies on.
            if not accept_succeeded:
                try:
                    writer.close()
                    # Wait for the underlying transport to actually drain
                    # so the slot is released before we decrement the
                    # active counter. Best-effort: failures here just
                    # mean the OS gets to clean up later.
                    await writer.wait_closed()
                except Exception as e:
                    log.debug(f"writer.close/wait_closed during cleanup raised: {e}")
            self._active_connections -= 1
