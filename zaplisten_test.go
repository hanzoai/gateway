//go:build legacy
// +build legacy

package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The ZAP listen topology has ONE rule with two halves, and this file is the
// lock on both:
//
//	the TLS terminator is the only thing on a PUBLIC interface, and
//	the plaintext ZAP server is only ever on LOOPBACK.
//
// Break either half and the same production manifest becomes one of two
// incidents. Both were live: k8s/hanzo/deployment.yaml set ZAP_LISTENER_PORT=9999
// and ZAP_INTERNAL_ADDR=127.0.0.1:9999 (the SAME port), and zaphttp_listener.go
// defaulted to ":9999" too — three spellings of one port, in one process,
// behind the PUBLIC zap-ingress LoadBalancer (zap.hanzo.ai:9999).
//
//	TLS binds first  -> it proxies every accepted conn to itself. crypto/tls
//	                    defers the handshake to the first Read, so Accept
//	                    returns before any certificate is exchanged: ONE bare
//	                    TCP SYN, unauthenticated, starts an unbounded
//	                    accept->self-dial->accept loop. Measured 201 accepts in
//	                    2s from a single connection, 2 fds and a goroutine each,
//	                    on the pod that also serves api.hanzo.ai.
//	ZAP-HTTP binds first -> the TLS terminator gets "address already in use",
//	                    which InitZapListenerFromEnv only slog.Error()s, and
//	                    PLAINTEXT ZAP is served on the public LB — every
//	                    developer's bearer token and prompt in cleartext.
//
// Neither failure path is fatal, so the pod reports Ready in both. That is why
// these are assertions and not comments.
//
// `legacy`-tagged, though half of what it locks (zap_listener.go, zaplisten.go)
// is in both builds. The two halves are ONE rule and splitting them across two
// files to satisfy a build tag would lose exactly the relationship this file
// exists to hold. executor.go — the only thing that starts either listener — is
// `legacy` too, and `make test` runs the tagged pass, so nothing here goes
// unexecuted.

// TestZapPlaintextServerBindsLoopbackOnly is the cleartext-exposure lock: the
// plaintext ZAP server must never be reachable off-host. ZAP has NO session
// crypto in ANY language — there is not one crypto/tls import in the whole
// zap-proto tree, and zaphttp dials and listens with bare net.Dial/net.Listen —
// so a non-loopback bind here IS plaintext on the network, whatever the
// manifest's "TLS 1.3+PQ" comment says.
func TestZapPlaintextServerBindsLoopbackOnly(t *testing.T) {
	// Unset, i.e. exactly what k8s/hanzo/deployment.yaml gives it: the default.
	t.Setenv(envZapHTTPListen, "")
	unsetenv(t, envZapHTTPListen)

	addr := zapHTTPListenAddr()
	if addr == "" {
		t.Fatal("plaintext ZAP server disabled by default; expected a loopback bind")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("zapHTTPListenAddr() = %q: not a host:port: %v", addr, err)
	}
	if !isLoopbackHost(host) {
		t.Errorf("plaintext ZAP server binds %q (host %q) — reachable off-host.\n"+
			"ZAP has no session crypto, so this serves cleartext to whatever can route to it;\n"+
			"in production that is the public zap-ingress LoadBalancer on :9999.", addr, host)
	}
}

// TestZapPlaintextServerNeverOnPublicPort is the collision lock. The public port
// belongs to the TLS terminator alone; two listeners in one process cannot share
// it, and the loser fails with a log line nobody reads.
func TestZapPlaintextServerNeverOnPublicPort(t *testing.T) {
	t.Setenv(envZapHTTPListen, "")
	unsetenv(t, envZapHTTPListen)

	internal := zapHTTPListenAddr()
	public := fmt.Sprintf(":%d", zapPublicPort)

	if portOf(t, internal) == portOf(t, public) {
		t.Errorf("plaintext ZAP server and the TLS terminator both default to port %d.\n"+
			"One process, one port: whichever binds first wins and the other dies with a\n"+
			"log-only error, leaving either a self-dial loop or cleartext on the public LB.",
			portOf(t, public))
	}
}

// TestZapListenerRefusesSelfDial is the loop lock, at the layer that can still
// refuse: a terminator told to forward to its own address is misconfigured, and
// must say so at startup instead of discovering it one accept at a time.
func TestZapListenerRefusesSelfDial(t *testing.T) {
	self := freePort(t) // 127.0.0.1:<ephemeral>
	port := portOf(t, self)

	cert, key := writeSelfSignedPair(t)
	err := StartZapListener(ZapListenerConfig{
		Port:         port,
		CertFile:     cert,
		KeyFile:      key,
		InternalAddr: self, // the production shape: same port as the listener
	})
	defer StopZapListener()

	if err == nil {
		t.Fatalf("StartZapListener(port=%d, internal=%s) accepted a self-dial config.\n"+
			"Every accepted connection would be proxied back into this listener; a single\n"+
			"unauthenticated TCP SYN then loops until the pod runs out of file descriptors.",
			port, self)
	}
	if !strings.Contains(err.Error(), "itself") {
		t.Errorf("error should name the cause (forwarding to itself); got: %v", err)
	}
}

// TestZapListenerSelfDialDoesNotAmplify is the same defect measured rather than
// asserted: with the guard in place a refused listener accepts nothing, so one
// inbound connection can never become many. Bounded so a regression fails the
// test instead of the machine.
func TestZapListenerSelfDialDoesNotAmplify(t *testing.T) {
	self := freePort(t)
	port := portOf(t, self)
	cert, key := writeSelfSignedPair(t)

	if err := StartZapListener(ZapListenerConfig{
		Port: port, CertFile: cert, KeyFile: key, InternalAddr: self,
	}); err == nil {
		t.Fatal("listener started on a self-dial config; guard missing")
	}
	defer StopZapListener()

	// Nothing should be listening: the guard refused before tls.Listen.
	var opened int64
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", self, 50*time.Millisecond)
		if err != nil {
			break
		}
		atomic.AddInt64(&opened, 1)
		c.Close()
		if atomic.LoadInt64(&opened) > 4 {
			t.Fatalf("a refused self-dial listener is still accepting (%d conns) — "+
				"the amplification path is open", opened)
		}
	}
	if n := atomic.LoadInt64(&opened); n != 0 {
		t.Errorf("refused listener accepted %d connections; want 0", n)
	}
}

// TestZapListenerRefusesNonLoopbackInternal is the other half of the same
// refusal: the inward leg is PLAINTEXT ZAP, so a routable InternalAddr puts the
// bytes this listener just decrypted straight back on the network. Different
// port, so the self-dial guard does not fire — the loopback rule has to.
func TestZapListenerRefusesNonLoopbackInternal(t *testing.T) {
	port := portOf(t, freePort(t))
	cert, key := writeSelfSignedPair(t)

	err := StartZapListener(ZapListenerConfig{
		Port: port, CertFile: cert, KeyFile: key,
		InternalAddr: "10.0.0.5:9998", // routable, and a DIFFERENT port
	})
	defer StopZapListener()

	if err == nil {
		t.Fatal("StartZapListener accepted a routable internal address — " +
			"decrypted ZAP would be forwarded in the clear across the cluster network")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error should name the cause (not loopback); got: %v", err)
	}
}

// portOf extracts the port from a bind address, tolerating a bare ":9999".
func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	n := 0
	if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
		t.Fatalf("port %q of %q: %v", p, addr, err)
	}
	return n
}

// unsetenv removes a variable for the duration of the test and restores it
// after. t.Setenv cannot express "absent" — it only sets — and absent is the
// case that matters here, because it is what the production manifest gives
// GATEWAY_ZAP_LISTEN.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unsetenv(%s): %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev)
		} else {
			os.Unsetenv(key)
		}
	})
}

// writeSelfSignedPair writes a throwaway cert/key to the test's temp dir and
// returns their paths. The guards under test run BEFORE tls.LoadX509KeyPair, so
// these only have to be loadable — never valid to anyone. Generated rather than
// checked in, so there is no key material in the tree pretending to be inert.
func writeSelfSignedPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "zap-listener-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}
