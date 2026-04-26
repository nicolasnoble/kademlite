# kademlite

[![CI](https://github.com/nicolasnoble/kademlite/actions/workflows/ci.yml/badge.svg)](https://github.com/nicolasnoble/kademlite/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/nicolasnoble/kademlite/graph/badge.svg)](https://codecov.io/gh/nicolasnoble/kademlite)
[![PyPI](https://img.shields.io/pypi/v/kademlite.svg)](https://pypi.org/project/kademlite/)
[![Python](https://img.shields.io/pypi/pyversions/kademlite.svg)](https://pypi.org/project/kademlite/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/nicolasnoble/kademlite#license)

Lightweight asyncio-native pure-Python Kademlia DHT implementation.

## What it is

A minimal, single-purpose libp2p Kademlia stack for Python applications that want peer-direct service discovery and metadata coordination without dragging in the full libp2p ecosystem or its native-C dependencies. Wire-compatible with [rust-libp2p](https://github.com/libp2p/rust-libp2p) and [go-libp2p](https://github.com/libp2p/go-libp2p) for `PUT_VALUE`, `GET_VALUE`, `FIND_NODE`, and `PING` - cross-implementation interop is exercised in CI against reference binaries from both.

## Why kademlite

- **asyncio-native.** Drops directly into modern asyncio Python applications without anyio bridging.
- **Zero native C dependencies.** Just `cryptography` + `protobuf`. Installs cleanly in restricted-deployment environments where the larger libp2p Python stack's C-dep chain (libsodium, libsecp256k1, GMP) doesn't.
- **Single protocol stack.** TCP + Noise XX (Ed25519/X25519/ChaCha20-Poly1305) + Yamux + Kademlia (`/ipfs/kad/1.0.0`). No pluggable transports, no relay, no pubsub - just the minimum needed for peer-direct DHT operations.
- **Bootstrap mechanisms for cluster deployments.** Explicit multiaddrs, K8s headless DNS service discovery, SLURM hostlist parsing, and mDNS for single-LAN.
- **CI-tested cross-implementation interop.** Every commit runs against reference rust-libp2p and go-libp2p binaries to verify wire compatibility. Wire-compat isn't claimed - it's mechanically verified.

## Install

```bash
pip install kademlite
```

Requires Python 3.10+.

## Quick start

```python
import asyncio
from kademlite import DhtNode

async def main():
    node = DhtNode()
    await node.start(
        listen_host="0.0.0.0",
        listen_port=4001,
        bootstrap_peers=["/ip4/192.168.1.10/tcp/4001/p2p/12D3KooW..."],
    )

    await node.put(b"my-key", b"my-value")
    value = await node.get(b"my-key")

    await node.stop()

asyncio.run(main())
```

Bootstrap can also use K8s headless DNS, SLURM hostlists, or mDNS (see `DhtNode.start()` keyword arguments).

## Scope

**In scope:**

- Kademlia operations: `PUT_VALUE`, `GET_VALUE`, `FIND_NODE`, `PING`
- Wire compatibility with rust-libp2p and go-libp2p on `/ipfs/kad/1.0.0`
- Bootstrap via explicit multiaddrs, K8s DNS, SLURM hostlists, mDNS
- Identify protocol with push notifications
- Connection-close detection and dead peer eviction

**Not in scope:**

- `ADD_PROVIDER` / `GET_PROVIDERS` (IPFS-style content discovery)
- Alternative transports (QUIC, WebRTC, WebSocket)
- Alternative security (TLS, plaintext)
- Pubsub (gossipsub, floodsub)
- Relay / hole-punching
- Anything from the broader libp2p modular toolkit

If you need any of those, [py-libp2p](https://github.com/libp2p/py-libp2p) is the canonical Python libp2p implementation and supports the full toolkit.

## Status

Alpha. CI-verified wire compatibility with rust-libp2p and go-libp2p reference implementations across all kad-dht core operations. APIs may shift before v1.0.

## License

Dual-licensed under MIT or Apache-2.0, at your choice. See `LICENSE-MIT`, `LICENSE-APACHE`, and `AUTHORS` for details.
