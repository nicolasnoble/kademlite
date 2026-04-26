// Copyright (c) The kademlite Authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// Go side of the libp2p Kademlia DHT interop test.
//
// Modes:
//
//	--mode put : Start a node, put a record, print the multiaddr, wait.
//	--mode get : Connect to a peer, get the record, verify, exit.
//
// This binary mirrors the behavior of the Rust counterpart in ../rust_node
// so that the Python test harness in tests/test_interop.py can drive either
// implementation interchangeably.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
)

const (
	kadProtocolID = protocol.ID("/ipfs/kad/1.0.0")
	identifyAgent = "/kad-interop/0.1.0"
	recordTTL     = 300 * time.Second
)

type args struct {
	mode        string
	key         string
	value       string
	peer        string
	timeoutSecs uint64
}

func parseArgs() *args {
	a := &args{}
	flag.StringVar(&a.mode, "mode", "", `"put" or "get"`)
	flag.StringVar(&a.key, "key", "/test/model:test-model:worker:0", "Key to store/retrieve")
	flag.StringVar(&a.value, "value",
		`{"rank":0,"tensors":[{"name":"layer.0.weight","size":1024}]}`,
		"Value to store (put mode only)")
	flag.StringVar(&a.peer, "peer", "", "Peer multiaddr to connect to (get mode only)")
	flag.Uint64Var(&a.timeoutSecs, "timeout-secs", 30, "How long to wait for operations (seconds)")
	flag.Parse()
	return a
}

func logInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[info] "+format+"\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[warn] "+format+"\n", args...)
}

// blankValidator accepts any record - mirrors the Rust binary's MemoryStore
// which has no validator chain attached.
type blankValidator struct{}

func (blankValidator) Validate(_ string, _ []byte) error        { return nil }
func (blankValidator) Select(_ string, _ [][]byte) (int, error) { return 0, nil }

func buildHost() (host.Host, error) {
	return libp2p.New(
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.UserAgent(identifyAgent),
		libp2p.ProtocolVersion(identifyAgent),
	)
}

// printListenAddr prints a /ip4/.../tcp/.../p2p/<peer-id> multiaddr to stdout.
// The Python harness parses this line with a strict regex:
//
//	/ip4/([^/]+)/tcp/(\d+)/p2p/(.+)
//
// To stay friendly to that regex and tunnel-style "0.0.0.0 -> 127.0.0.1"
// rewrites in the harness, prefer a loopback (127.0.0.1) address when
// available, falling back to any other /ip4 listen address.
func printListenAddr(h host.Host) (multiaddr.Multiaddr, error) {
	pidComp, err := multiaddr.NewComponent("p2p", h.ID().String())
	if err != nil {
		return nil, fmt.Errorf("build p2p component: %w", err)
	}

	var loopback, other multiaddr.Multiaddr
	for _, addr := range h.Addrs() {
		ip4, _ := addr.ValueForProtocol(multiaddr.P_IP4)
		if ip4 == "" {
			continue
		}
		full := addr.Encapsulate(pidComp)
		if strings.HasPrefix(ip4, "127.") {
			loopback = full
			break
		}
		if other == nil {
			other = full
		}
	}

	chosen := loopback
	if chosen == nil {
		chosen = other
	}
	if chosen == nil {
		return nil, fmt.Errorf("no /ip4 listen address available")
	}

	logInfo("Listening on: %s", chosen)
	fmt.Printf("LISTEN_ADDR=%s\n", chosen)
	return chosen, nil
}

func newDHT(ctx context.Context, h host.Host) (*dht.IpfsDHT, error) {
	kdht, err := dht.New(ctx, h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix(""),
		dht.V1ProtocolOverride(kadProtocolID),
		dht.MaxRecordAge(recordTTL),
		// Permissive validator: accept any key/value, matching the Rust
		// binary's MemoryStore which performs no validation.
		dht.Validator(record.NamespacedValidator{
			"":     blankValidator{},
			"pk":   blankValidator{},
			"ipns": blankValidator{},
			"test": blankValidator{},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create DHT: %w", err)
	}
	if err := kdht.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap DHT: %w", err)
	}
	return kdht, nil
}

func runPut(ctx context.Context, _ host.Host, kdht *dht.IpfsDHT, a *args) error {
	deadline, cancel := context.WithTimeout(ctx, time.Duration(a.timeoutSecs)*time.Second)
	defer cancel()

	// In a single-node DHT, PutValue may complete locally or warn that no
	// peers were found. The Rust binary tolerates this: the local store
	// holds the record, ready to serve incoming queries.
	if err := kdht.PutValue(deadline, a.key, []byte(a.value)); err != nil {
		logWarn("PutValue: %v (record stored locally for incoming queries)", err)
	}

	logInfo("Record stored locally, waiting for peers to query...")

	// Block until the timeout elapses (mirrors Rust's `timeout(deadline, ...)`).
	<-deadline.Done()

	logInfo("Put node shutting down.")
	return nil
}

func runGet(ctx context.Context, h host.Host, kdht *dht.IpfsDHT, a *args) error {
	if a.peer == "" {
		return fmt.Errorf("--peer is required in get mode")
	}

	maddr, err := multiaddr.NewMultiaddr(a.peer)
	if err != nil {
		return fmt.Errorf("parse --peer multiaddr: %w", err)
	}
	pi, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("derive AddrInfo: %w", err)
	}

	logInfo("Dialing peer: %s", a.peer)
	dialCtx, dialCancel := context.WithTimeout(ctx, time.Duration(a.timeoutSecs)*time.Second)
	defer dialCancel()
	if err := h.Connect(dialCtx, *pi); err != nil {
		fmt.Fprintf(os.Stderr, "Test failed: dial peer: %v\n", err)
		fmt.Println("RESULT=FAIL")
		os.Exit(1)
	}
	logInfo("Connected to: %s", pi.ID)

	// Wait for identify so the peerstore picks up listen addresses.
	idDeadline := time.Duration(a.timeoutSecs) * time.Second
	if err := waitForIdentify(ctx, h, pi.ID, idDeadline); err != nil {
		logWarn("waitForIdentify: %v (continuing)", err)
	}

	// Small delay to let routing tables settle (matches Rust binary).
	time.Sleep(500 * time.Millisecond)

	// Manually add the peer to the routing table; some go-libp2p-kad-dht
	// versions don't auto-populate from Identify when ProtocolPrefix is empty.
	kdht.RoutingTable().TryAddPeer(pi.ID, true, true)

	queryCtx, queryCancel := context.WithTimeout(ctx, time.Duration(a.timeoutSecs)*time.Second)
	defer queryCancel()

	logInfo("Started get_record query for key=%q", a.key)
	value, err := kdht.GetValue(queryCtx, a.key)
	if err != nil {
		if queryCtx.Err() == context.DeadlineExceeded {
			fmt.Fprintf(os.Stderr, "Test timed out after %ds\n", a.timeoutSecs)
			fmt.Println("RESULT=TIMEOUT")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Test failed: %v\n", err)
		fmt.Println("RESULT=FAIL")
		os.Exit(1)
	}

	logInfo("Got record: key=%q, value=%s", a.key, string(value))
	fmt.Printf("RECORD_VALUE=%s\n", string(value))
	logInfo("Test passed! Retrieved value: %s", string(value))
	fmt.Println("RESULT=OK")
	return nil
}

func waitForIdentify(ctx context.Context, h host.Host, pid peer.ID, deadline time.Duration) error {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadlineCtx.Done():
			return fmt.Errorf("identify wait deadline exceeded")
		case <-ticker.C:
			av, err := h.Peerstore().Get(pid, "AgentVersion")
			if err == nil && av != nil {
				logInfo("Identified peer %s: AgentVersion=%v", pid, av)
				return nil
			}
		}
	}
}

func main() {
	a := parseArgs()
	if a.mode == "" {
		fmt.Fprintln(os.Stderr, "Error: --mode is required (put or get)")
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, err := buildHost()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Build host: %v\n", err)
		os.Exit(1)
	}
	defer h.Close()

	kdht, err := newDHT(ctx, h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Build DHT: %v\n", err)
		os.Exit(1)
	}
	defer kdht.Close()

	if _, err := printListenAddr(h); err != nil {
		fmt.Fprintf(os.Stderr, "Print listen addr: %v\n", err)
		os.Exit(1)
	}

	switch a.mode {
	case "put":
		if err := runPut(ctx, h, kdht, a); err != nil {
			fmt.Fprintf(os.Stderr, "put failed: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if err := runGet(ctx, h, kdht, a); err != nil {
			fmt.Fprintf(os.Stderr, "get failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", a.mode)
		os.Exit(2)
	}
}
