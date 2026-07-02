// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

// Tests for the lazy peer resolver (peer_resolver.go) — the core of the
// HIP-0110 boot fix. The contract under test:
//
//   - NewLazyPicker boots with the ZAP backends ABSENT: warming a dead
//     address must NOT panic, NOT block past the dial timeout, and NOT be
//     fatal. The returned picker is usable.
//   - A picker over dead backends returns "" for every path (so node.Call
//     gets a benign "peer not found" instead of the process dying).
//   - RegisterRelay + BuildApp succeed with a lazy picker over dead
//     backends — i.e. the whole gateway wiring stands up with no backend.
//   - When a backend IS reachable, the picker resolves its handshake-
//     learned peerID and caches it (resolve is idempotent and a no-op dial
//     the second time), so a healthy backend behaves exactly like the old
//     eager path. /v1/base/* routes to base, everything else to cloud.

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	"github.com/luxfi/zap/forward"
)

// deadAddr is a loopback address with nothing listening. ConnectDirectID
// fails fast against it (connection refused), which is the steady-state the
// gateway must boot through when cloud:9090 / base:9091 don't exist.
const deadAddr = "127.0.0.1:1" // port 1 is privileged + unbound -> refused

// startedNode brings up a NoDiscovery ZAP node on an ephemeral port for a
// test and registers Stop() cleanup. Mirrors the production node config.
func startedNode(t *testing.T, id string) *zaplib.Node {
	t.Helper()
	n := zaplib.NewNode(zaplib.NodeConfig{NodeID: id, Port: 0, NoDiscovery: true})
	if err := n.Start(); err != nil {
		t.Fatalf("%s start: %v", id, err)
	}
	t.Cleanup(n.Stop)
	return n
}

// TestNewLazyPicker_BootsWithBackendsAbsent is the headline boot-fix test:
// constructing the picker against two dead backends must return without
// panicking or hanging, and the picker must yield "" (not crash) for any
// path. This is exactly the prod condition that previously os.Exit(1)'d.
func TestNewLazyPicker_BootsWithBackendsAbsent(t *testing.T) {
	node := startedNode(t, "gateway")

	done := make(chan forward.PeerPicker, 1)
	go func() {
		// NewLazyPicker warms both (dead) backends best-effort, then returns.
		done <- NewLazyPicker(node, luxlog.NewNoOpLogger(), deadAddr, deadAddr)
	}()

	var pick forward.PeerPicker
	select {
	case pick = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("NewLazyPicker blocked with backends absent — boot would hang/crash")
	}
	if pick == nil {
		t.Fatal("NewLazyPicker returned nil picker")
	}

	// Every route resolves to "" (dead backend) — never a panic.
	for _, path := range []string{"/v1/chat/completions", "/v1/base/records", "/"} {
		if got := pick(path); got != "" {
			t.Errorf("pick(%q) over dead backend = %q, want \"\"", path, got)
		}
	}
}

// TestRegisterRelay_BootsWithLazyPickerNoBackends proves the full relay
// wiring (RegisterRelay) + the liveness HTTP app (BuildApp) stand up when
// the backends are absent — no error, no panic. The pod would boot and
// serve healthz in this state.
func TestRegisterRelay_BootsWithLazyPickerNoBackends(t *testing.T) {
	node := startedNode(t, "gateway")

	pick := NewLazyPicker(node, luxlog.NewNoOpLogger(), deadAddr, deadAddr)
	if err := RegisterRelay(RelayDeps{
		Logger: luxlog.NewNoOpLogger(),
		Node:   node,
		Pick:   pick,
		Auth:   AuthConfig{Enabled: false},
	}); err != nil {
		t.Fatalf("RegisterRelay with absent backends returned error: %v", err)
	}

	app, err := BuildApp(RouterDeps{
		Logger:    luxlog.NewNoOpLogger(),
		ZAPNode:   node,
		CloudAddr: deadAddr,
		BaseAddr:  deadAddr,
	})
	if err != nil {
		t.Fatalf("BuildApp with absent backends returned error: %v", err)
	}

	// healthz must serve 200 — the liveness surface the k8s probe needs.
	// app.Fiber().Test drives the router in-memory (no real listener).
	req, _ := http.NewRequest(http.MethodGet, "http://gateway/healthz", nil)
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("healthz Test: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200 (HTTP must serve with backends absent)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var got map[string]string
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("healthz body not JSON: %q (%v)", body, err)
	}
	if got["status"] != "ok" {
		t.Errorf("healthz body status = %q, want ok", got["status"])
	}
}

// startedNodeOnPort brings up a NoDiscovery node on an explicit port so the
// test knows the dial address. Cleanup registered.
func startedNodeOnPort(t *testing.T, id string, port int) *zaplib.Node {
	t.Helper()
	n := zaplib.NewNode(zaplib.NodeConfig{NodeID: id, Port: port, NoDiscovery: true})
	if err := n.Start(); err != nil {
		t.Fatalf("%s start on :%d: %v", id, port, err)
	}
	t.Cleanup(n.Stop)
	return n
}

// TestLazyPicker_ResolvesAndRoutesWithLiveBackends proves ZAP still works
// when the backends exist: the lazy picker dials each live backend on first
// use, learns its peerID, routes /v1/base/* to base and everything else to
// cloud, and caches the result (a second resolve does not change the id).
func TestLazyPicker_ResolvesAndRoutesWithLiveBackends(t *testing.T) {
	gw := startedNode(t, "gateway")
	cloudPort := reservePort(t)
	basePort := reservePort(t)
	cloud := startedNodeOnPort(t, "cloud-be", cloudPort)
	base := startedNodeOnPort(t, "base-be", basePort)

	cloudAddr := "127.0.0.1:" + strconv.Itoa(cloudPort)
	baseAddr := "127.0.0.1:" + strconv.Itoa(basePort)

	r := newPeerResolver(gw, luxlog.NewNoOpLogger())
	pick := r.picker(baseAddr, cloudAddr)

	cloudPeer := pick("/v1/chat/completions")
	if cloudPeer != cloud.NodeID() {
		t.Errorf("cloud route peerID = %q, want %q", cloudPeer, cloud.NodeID())
	}
	basePeer := pick("/v1/base/records")
	if basePeer != base.NodeID() {
		t.Errorf("base route peerID = %q, want %q", basePeer, base.NodeID())
	}

	// Idempotent + cached: resolving again yields the same id and adds no
	// new connection (ConnectDirectID dedups), so a healthy backend is
	// dialed exactly once.
	if again := pick("/v1/chat/completions"); again != cloudPeer {
		t.Errorf("second cloud resolve = %q, want cached %q", again, cloudPeer)
	}
	peers := gw.Peers()
	if len(peers) != 2 {
		t.Errorf("gateway holds %d peer conns, want 2 (one per backend, no dupes): %v", len(peers), peers)
	}
}

// TestLazyPicker_RecoversWhenBackendComesUp proves the retry property: a
// path that resolved to "" while its backend was down resolves correctly
// once the backend exists, with no restart. (Boot through outage, then heal.)
func TestLazyPicker_RecoversWhenBackendComesUp(t *testing.T) {
	gw := startedNode(t, "gateway")

	// Reserve a port, keep it CLOSED so the first dial is refused, then
	// bring a node up on that exact port and confirm the next resolve wins.
	port := reservePort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)

	r := newPeerResolver(gw, luxlog.NewNoOpLogger())
	pick := r.picker(addr, addr)

	if got := pick("/v1/chat/completions"); got != "" {
		t.Fatalf("resolve before backend up = %q, want \"\"", got)
	}

	// Backend appears on the reserved port.
	be := zaplib.NewNode(zaplib.NodeConfig{NodeID: "late-be", Port: port, NoDiscovery: true})
	if err := be.Start(); err != nil {
		t.Fatalf("late backend start on :%d: %v", port, err)
	}
	t.Cleanup(be.Stop)

	// Retry resolves now (lazy picker re-dials on each miss).
	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := pick("/v1/chat/completions"); got == be.NodeID() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolve after backend up never returned %q", be.NodeID())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestPeerResolver_NilPickFallsBackToStatic guards the RegisterRelay
// contract that a nil Pick still works via the static pickPeer path (the
// pre-existing e2e test relies on this).
func TestPeerResolver_NilPickFallsBackToStatic(t *testing.T) {
	node := startedNode(t, "gateway")
	err := RegisterRelay(RelayDeps{
		Logger:      luxlog.NewNoOpLogger(),
		Node:        node,
		Pick:        nil, // exercise the static fallback
		BasePeerID:  "base-id",
		CloudPeerID: "cloud-id",
		Auth:        AuthConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("RegisterRelay with nil Pick (static fallback) errored: %v", err)
	}
}

// reservePort grabs a free TCP port and releases it, returning the number.
// Same approach as freePortInt in gate_test.go; duplicated-free is fine on
// loopback for tests.
func reservePort(t *testing.T) int {
	t.Helper()
	return freePortInt(t)
}
