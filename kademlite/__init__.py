# Copyright (c) The kademlite Authors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""kademlite: minimal, asyncio-native libp2p implementation.

Supports exactly one protocol stack: TCP + Noise XX (Ed25519) + Yamux + Kademlia.
No pluggable transports, no relay, no pubsub. Purpose-built for DHT metadata exchange.
"""

from .dht import DhtNode  # noqa: F401

__all__ = ["DhtNode"]
