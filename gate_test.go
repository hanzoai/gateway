// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

// Tests for the gateway relay gate (gate.go) and RegisterRelay (build_app.go).
//
// Two layers:
//   - Direct gate tests: the forward.Gate is just func(ctx, *Forward) ->
//     (*Response, error); we feed crafted Forwards (valid/invalid/missing
//     JWT, API key, body-present) and assert identity injection or the deny
//     Response. These reuse the JWKS harness from
//     auth_middleware_security_test.go (newTestJWKS/signToken/validClaims).
//   - End-to-end registration test: a real ingress→gateway→backend ZAP
//     chain where the gateway is wired by RegisterRelay. Proves forward.Relay
//     is registered and a valid JWT's identity reaches the backend.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	luxlog "github.com/luxfi/log"
	zaplib "github.com/luxfi/zap"
	"github.com/luxfi/zap/forward"
)

// gateConfig builds an AuthConfig pointed at a live test JWKS server.
func gateConfig(t *testing.T, tj *testJWKS, requireAuth bool) (AuthConfig, func()) {
	t.Helper()
	srv := tj.serveJWKS(t)
	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     srv.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: requireAuth,
	}
	return cfg, srv.Close
}

// forwardWithHeaders builds a Forward whose Headers JSON carries the given
// header map and whose Body is non-empty (so tests can assert the gate
// never reads it).
func forwardWithHeaders(t *testing.T, path string, hdrs map[string][]string) forward.Forward {
	t.Helper()
	hj, err := json.Marshal(hdrs)
	if err != nil {
		t.Fatalf("marshal headers: %v", err)
	}
	return forward.Forward{
		Method:  http.MethodPost,
		Path:    path,
		Headers: hj,
		Body:    []byte(`{"prompt":"do not read me"}`),
	}
}

// --- valid JWT -> identity injected, allow -----------------------------

func TestGateValidJWTInjectsIdentity(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true)
	defer closeJWKS()

	// An ORG-level admin (validClaims owner="hanzo", IsAdmin=true — an org owner).
	// The money/admin bit MUST NOT be granted; only Live (real-money mode).
	claims := validClaims(cfg.Issuer, cfg.Audiences[0])
	claims.IsAdmin = true
	token := tj.signToken(t, claims)

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Authorization": {"Bearer " + token},
	})
	bodyBefore := append([]byte(nil), f.Body...)

	deny, err := gate(context.Background(), &f)
	if err != nil {
		t.Fatalf("gate returned error: %v", err)
	}
	if deny != nil {
		t.Fatalf("valid JWT denied: status=%d body=%s", deny.Status, deny.Body)
	}
	if f.TenantID != "hanzo" {
		t.Errorf("TenantID: got %q want hanzo", f.TenantID)
	}
	if f.UserID != "alice" {
		t.Errorf("UserID: got %q want alice", f.UserID)
	}
	if !f.IsAdmin {
		t.Error("IsAdmin: got false want true")
	}
	// Org-level admin -> Live ONLY (the Admin money bit is global-admin-only).
	if wantBits := permissionBits["live"]; f.Permissions != wantBits {
		t.Errorf("org-admin Permissions: got %d want %d (Live only, no Admin bit)", f.Permissions, wantBits)
	}
	if f.Permissions&permissionBits["admin"] != 0 {
		t.Errorf("org-admin was granted the Admin money bit (perms=%d) — free-money hole", f.Permissions)
	}
	// The gate must not have touched the body.
	if string(f.Body) != string(bodyBefore) {
		t.Errorf("gate mutated f.Body: got %q want %q", f.Body, bodyBefore)
	}
}

// TestGatePlatformSudoGetsAdminBit proves the OTHER side of the money gate: a
// PLATFORM-sudo principal — owner=="admin" — DOES get the Admin|Live bits, so
// legitimate admin/service tooling keeps working. Gated on the org, no boolean.
func TestGatePlatformSudoGetsAdminBit(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true)
	defer closeJWKS()

	claims := validClaims(cfg.Issuer, cfg.Audiences[0])
	claims.Owner = "admin" // global admin org
	claims.IsAdmin = true
	token := tj.signToken(t, claims)

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Authorization": {"Bearer " + token},
	})
	if deny, err := gate(context.Background(), &f); err != nil || deny != nil {
		t.Fatalf("global-admin JWT unexpectedly denied: deny=%v err=%v", deny, err)
	}
	wantBits := permissionBits["admin"] | permissionBits["live"]
	if f.Permissions != wantBits {
		t.Errorf("global-admin Permissions: got %d want %d (Admin|Live)", f.Permissions, wantBits)
	}
}

// --- missing token + RequireAuth -> 401 deny ---------------------------

func TestGateMissingTokenRequireAuthDenies(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true) // RequireAuth = true
	defer closeJWKS()

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Content-Type": {"application/json"},
	})

	deny, err := gate(context.Background(), &f)
	if err != nil {
		t.Fatalf("gate returned error: %v", err)
	}
	if deny == nil {
		t.Fatal("missing token with RequireAuth=true was allowed, want 401")
	}
	if deny.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", deny.Status)
	}
	var body map[string]string
	if err := json.Unmarshal(deny.Body, &body); err != nil {
		t.Fatalf("deny body not JSON: %q (%v)", deny.Body, err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("deny error: got %q want unauthorized", body["error"])
	}
	if f.TenantID != "" || f.UserID != "" {
		t.Errorf("identity injected on deny: tenant=%q user=%q", f.TenantID, f.UserID)
	}
}

// --- missing token, RequireAuth=false -> allow, no identity ------------

func TestGateMissingTokenOptionalAllows(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, false) // RequireAuth = false
	defer closeJWKS()

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Content-Type": {"application/json"},
	})

	deny, err := gate(context.Background(), &f)
	if err != nil {
		t.Fatalf("gate returned error: %v", err)
	}
	if deny != nil {
		t.Fatalf("tokenless optional request denied: status=%d", deny.Status)
	}
	if f.TenantID != "" || f.UserID != "" {
		t.Errorf("identity injected without a token: tenant=%q user=%q", f.TenantID, f.UserID)
	}
}

// --- invalid JWT (wrong issuer) -> 401 deny ----------------------------

func TestGateInvalidJWTDenies(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, false)
	defer closeJWKS()

	// Sign with a deliberately wrong issuer — validation must reject it.
	claims := validClaims("https://evil.example", cfg.Audiences[0])
	token := tj.signToken(t, claims)

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Authorization": {"Bearer " + token},
	})

	deny, err := gate(context.Background(), &f)
	if err != nil {
		t.Fatalf("gate returned error: %v", err)
	}
	if deny == nil {
		t.Fatal("invalid JWT was allowed, want 401")
	}
	if deny.Status != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", deny.Status)
	}
}

// --- opaque API key -> allow, no JWT identity --------------------------

func TestGateAPIKeyPassesThrough(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true) // even with RequireAuth, API keys pass
	defer closeJWKS()

	gate := newGate(cfg)
	f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
		"Authorization": {"Bearer sk-live-abc123"},
	})

	deny, err := gate(context.Background(), &f)
	if err != nil {
		t.Fatalf("gate returned error: %v", err)
	}
	if deny != nil {
		t.Fatalf("API key denied: status=%d", deny.Status)
	}
	if f.TenantID != "" || f.UserID != "" {
		t.Errorf("API key produced edge identity: tenant=%q user=%q", f.TenantID, f.UserID)
	}
}

// --- disabled gate -> allow everything, no identity --------------------

func TestGateDisabledAllowsAll(t *testing.T) {
	gate := newGate(AuthConfig{Enabled: false})
	f := forwardWithHeaders(t, "/v1/anything", map[string][]string{
		"Authorization": {"Bearer garbage"},
	})
	deny, err := gate(context.Background(), &f)
	if err != nil || deny != nil {
		t.Fatalf("disabled gate did not allow: deny=%v err=%v", deny, err)
	}
	if f.TenantID != "" {
		t.Errorf("disabled gate injected identity: %q", f.TenantID)
	}
}

// --- trust boundary: forged envelope identity is stripped --------------

// TestGateStripsForgedIdentity proves a client cannot smuggle identity past
// the relay. forward.Forwarder lifts X-Org-Id/X-User-Id headers into the
// Forward's TenantID/UserID fields; the gate must clear them on every allow
// path that is not a validated JWT. We assert it on the API-key path (a
// non-JWT allow) and on the no-token optional path.
func TestGateStripsForgedIdentity(t *testing.T) {
	tj := newTestJWKS(t)

	// API-key path: RequireAuth on, key passes, forged identity must die.
	t.Run("api_key_path", func(t *testing.T) {
		cfg, closeJWKS := gateConfig(t, tj, true)
		defer closeJWKS()
		gate := newGate(cfg)
		f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
			"Authorization": {"Bearer sk-live-key"},
		})
		// Attacker pre-seeds the envelope identity (as forward.Forwarder
		// would from forged X-Org-Id / X-User-Id client headers).
		f.TenantID = "victim-org"
		f.UserID = "victim-user"
		f.IsAdmin = true
		f.Permissions = 0x7fffffff

		deny, err := gate(context.Background(), &f)
		if err != nil || deny != nil {
			t.Fatalf("API key not allowed: deny=%v err=%v", deny, err)
		}
		if f.TenantID != "" || f.UserID != "" || f.IsAdmin || f.Permissions != 0 {
			t.Errorf("forged identity survived API-key path: tenant=%q user=%q admin=%v perms=%d",
				f.TenantID, f.UserID, f.IsAdmin, f.Permissions)
		}
	})

	// No-token optional path: forged identity must die there too.
	t.Run("no_token_path", func(t *testing.T) {
		cfg, closeJWKS := gateConfig(t, tj, false)
		defer closeJWKS()
		gate := newGate(cfg)
		f := forwardWithHeaders(t, "/v1/chat/completions", map[string][]string{
			"Content-Type": {"application/json"},
		})
		f.TenantID = "victim-org"
		f.IsAdmin = true

		deny, err := gate(context.Background(), &f)
		if err != nil || deny != nil {
			t.Fatalf("tokenless optional not allowed: deny=%v err=%v", deny, err)
		}
		if f.TenantID != "" || f.IsAdmin {
			t.Errorf("forged identity survived no-token path: tenant=%q admin=%v", f.TenantID, f.IsAdmin)
		}
	})
}

// --- pickPeer routing ---------------------------------------------------

func TestPickPeerRouting(t *testing.T) {
	pick := pickPeer("base-node", "cloud-node")
	cases := map[string]string{
		"/v1/base/records":      "base-node",
		"/v1/base/":             "base-node",
		"/v1/chat/completions":  "cloud-node",
		"/v1/iam/users/123":     "cloud-node",
		"/":                     "cloud-node",
		"/v1/basement/not-base": "cloud-node", // must not prefix-match /v1/base/
	}
	for path, want := range cases {
		if got := pick(path); got != want {
			t.Errorf("pick(%q): got %q want %q", path, got, want)
		}
	}
}

// --- end-to-end: RegisterRelay wires a working relay -------------------

// TestRegisterRelayEndToEnd stands up ingress -> gateway(RegisterRelay) ->
// backend over ZAP. It proves forward.Relay is registered on the gateway
// node and that a valid JWT's identity (X-Org-Id) reaches the backend.
func TestRegisterRelayEndToEnd(t *testing.T) {
	tj := newTestJWKS(t)
	cfg, closeJWKS := gateConfig(t, tj, true)
	defer closeJWKS()

	gwPort := freePortInt(t)
	bePort := freePortInt(t)
	ingress := zaplib.NewNode(zaplib.NodeConfig{NodeID: "ingress", Port: freePortInt(t), NoDiscovery: true})
	gw := zaplib.NewNode(zaplib.NodeConfig{NodeID: "gateway", Port: gwPort, NoDiscovery: true})
	backend := zaplib.NewNode(zaplib.NodeConfig{NodeID: "backend", Port: bePort, NoDiscovery: true})
	for _, n := range []*zaplib.Node{ingress, gw, backend} {
		if err := n.Start(); err != nil {
			t.Fatalf("%s start: %v", n.NodeID(), err)
		}
		defer n.Stop()
	}

	// Backend echoes the edge identity it received.
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{
			"org":  r.Header.Get(forward.HeaderOrgID),
			"user": r.Header.Get(forward.HeaderUserID),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	})
	forward.Serve(backend, backendHandler)

	// Gateway dials the backend and wires the relay via the production path.
	bePeerID, err := gw.ConnectDirectID("127.0.0.1:" + strconv.Itoa(bePort))
	if err != nil {
		t.Fatalf("gateway->backend: %v", err)
	}
	if err := RegisterRelay(RelayDeps{
		Logger:      luxlog.NewNoOpLogger(),
		Node:        gw,
		BasePeerID:  bePeerID, // single backend in this test: both route there
		CloudPeerID: bePeerID,
		Auth:        cfg,
	}); err != nil {
		t.Fatalf("RegisterRelay: %v", err)
	}

	// Ingress dials the gateway.
	if err := ingress.ConnectDirect("127.0.0.1:" + strconv.Itoa(gwPort)); err != nil {
		t.Fatalf("ingress->gateway: %v", err)
	}
	waitPeers(t, ingress)

	// Mint a valid JWT and drive a request through the relay.
	token := tj.signToken(t, validClaims(cfg.Issuer, cfg.Audiences[0]))
	req, _ := http.NewRequest(http.MethodGet, "http://gateway/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fwd := &forward.Forwarder{Node: ingress, Peer: "gateway"}
	resp, err := fwd.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("RoundTrip through relay: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var echoed map[string]string
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("decode backend echo %q: %v", body, err)
	}
	if echoed["org"] != "hanzo" {
		t.Errorf("backend saw X-Org-Id=%q want hanzo (identity did not survive relay)", echoed["org"])
	}
	if echoed["user"] != "alice" {
		t.Errorf("backend saw X-User-Id=%q want alice", echoed["user"])
	}
}

// --- helpers ------------------------------------------------------------

// freePortInt reserves an ephemeral TCP port and returns it as an int (the
// existing freePort in zaphttp_listener_test.go returns a ":NNNN" string;
// the ZAP NodeConfig.Port wants an int). The listener is closed immediately;
// the small reuse window is acceptable for tests on local loopback.
func freePortInt(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// waitPeers blocks until n has at least one connected peer or the deadline
// elapses.
func waitPeers(t *testing.T, n *zaplib.Node) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Peers()) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s saw no peers within deadline", n.NodeID())
}
