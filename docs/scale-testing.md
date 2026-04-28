# Scale Testing

The `tests/k8s/` directory contains a Kubernetes-based scale test harness for
kademlite. It validates that the DHT behaves correctly when deployed as a
clustered workload: cross-node routing, observed-IP detection, replication,
TTL expiry, concurrent multi-writer traffic, multi-hop iterative lookup, and
data survival across a rolling restart.

These tests cover behavior that the in-process pytest suite cannot reach,
because every node runs in its own pod with a real pod IP, real TCP
sockets, and DNS-driven peer discovery instead of `127.0.0.1` shortcuts.

## Prerequisites

- A Kubernetes cluster you can build images for and apply manifests to.
  Any distribution works:
  - **microk8s** (the default targets its built-in registry at
    `localhost:32000`)
  - **kind** with a local registry
  - **k3s** with a local or external registry
  - vanilla Kubernetes against any registry the cluster can pull from
- `kubectl` available in `PATH` (or set `KUBECTL` to a custom command;
  see below).
- `docker` for building the test image.
- A container registry the cluster can pull from. For microk8s the
  built-in `localhost:32000` registry works out of the box; for other
  setups override `IMAGE` with a tag your registry hosts.

## Running a small test

From the repository root:

```bash
cd tests/k8s
./run_k8s_test.sh --replicas 5
```

This builds the image, deploys 5 peer pods plus a test job, runs the
12 in-pod test scenarios, prints the results, and tears the namespace
down. Exit code is 0 if every scenario passed.

## Running the soak test

The soak test exercises data survival across a rolling restart. It
seeds 500 records into the DHT, kicks off `kubectl rollout restart`, and
samples availability every 10 seconds while pods are being replaced.
It needs at least 20 peers to be meaningful; if you ask for fewer, the
script bumps the count to 200 automatically.

```bash
./run_k8s_test.sh --soak --replicas 200
```

Use `--cleanup-only` to remove a previous run's namespace without
deploying a new one:

```bash
./run_k8s_test.sh --cleanup-only
```

## Configurable environment variables

| Variable | Default | Purpose |
|---|---|---|
| `KUBECTL` | `kubectl` | Command used to talk to the cluster. Set to `microk8s kubectl`, `k3s kubectl`, or `sudo kubectl` if your distribution wraps it. |
| `IMAGE` | `localhost:32000/dht-test:latest` | Image tag to build, push, and reference in the manifest. Override for kind/k3s/remote registries (e.g. `IMAGE=ghcr.io/me/dht-test:v1`). |

Examples:

```bash
# microk8s
KUBECTL="microk8s kubectl" ./run_k8s_test.sh --replicas 10

# kind with a local registry on port 5000
IMAGE=localhost:5000/dht-test:latest ./run_k8s_test.sh --replicas 10

# remote registry
IMAGE=registry.example.com/dht-test:v1 ./run_k8s_test.sh --replicas 50
```

## Test scenarios

The `test` role (default) runs 12 scenarios in sequence:

1. **basic_put_get** - sanity PUT and GET on the joining node
2. **cross_node_routing** - PUT/GET that has to traverse pod IPs
3. **observed_ip_detection** - confirms the node learns its real pod
   IP via Identify when bound to `0.0.0.0`
4. **routing_table_health** - routing table populated, every entry has
   addresses
5. **data_distribution** - records actually stored on remote peers, not
   just locally cached
6. **batch_records** - sequential PUT/GET batch (20 small, 200 at scale)
7. **per_record_ttl** - per-record TTL is honored and expires records
8. **concurrent_puts** - massive concurrent PUT/GET fan-out (10 small,
   200 at scale)
9. **multi_hop_lookup** - far-key lookup that needs iterative routing
10. **large_record** - record near the protocol max size, verifying
    cross-node transfer of bigger payloads
11. **cluster_flood** - floods `N*2` records to verify keyspace coverage
    and per-peer store efficiency (skipped when fewer than 20 peers)
12. **record_filter** - spawns a second node with a record filter and
    verifies accept/reject logic across the network

The `soak` role (`--soak`) runs an additional rolling-restart scenario
on top of the cluster the test job is already part of.

## Original validation

This harness was originally validated at 200-pod scale with rolling
restart soak runs (500 of 500 records preserved, 100 percent
availability across the rollout). It is included here so contributors
can reproduce and extend the same coverage on their own clusters.

## How discovery works

Each pod resolves the headless `kdl-dht` Service's DNS name and
bootstraps via kademlite's standard DNS provider. Bootstrap is
bounded: each peer connects to up to `K=20` resolved neighbors and
then lets Kademlia self-lookup populate the rest of its routing
table, so a 200-pod cluster does not require every peer to hold
connections to every other peer. Scaling the Deployment up or down
is a single `kubectl scale` away with no configuration changes.

See [`discovery.md`](discovery.md) for the full discovery model
across all four bootstrap providers (explicit multiaddrs, DNS, SLURM,
mDNS), the Noise + Identify handshake details, and the maintenance
and eviction loops.
