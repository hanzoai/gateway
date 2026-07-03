//go:build legacy
// +build legacy

package gateway

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	zaphttp "github.com/zap-proto/http"

	"github.com/luraproject/lura/v2/logging"
)

// freePort grabs an ephemeral port and returns it as a ":NNNN" string.
// Closing the listener before returning leaves a small race window;
// acceptable for tests on local loopback.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// waitForTCP blocks until a TCP dial to addr succeeds or the deadline
// passes. Used to defeat the listener-startup race in goroutine boot.
func waitForTCP(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitForTCP: %s not reachable within %s", addr, timeout)
}

// TestZapHTTPListenAddr verifies the env-knob parsing contract. This is
// the single source of truth for how operators turn the listener on/off.
func TestZapHTTPListenAddr(t *testing.T) {
	t.Setenv(envZapHTTPListen, "")
	tests := []struct {
		name string
		set  bool
		val  string
		want string
	}{
		{"unset → default", false, "", defaultZapHTTPAddr},
		{"empty → disabled", true, "", ""},
		{"off → disabled", true, "off", ""},
		{"OFF → disabled", true, "OFF", ""},
		{"false → disabled", true, "false", ""},
		{"0 → disabled", true, "0", ""},
		{"explicit addr", true, ":12345", ":12345"},
		{"hostport", true, "127.0.0.1:9999", "127.0.0.1:9999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(envZapHTTPListen, tt.val)
			} else {
				os.Unsetenv(envZapHTTPListen)
			}
			got := zapHTTPListenAddr()
			if got != tt.want {
				t.Errorf("zapHTTPListenAddr()=%q want %q", got, tt.want)
			}
		})
	}
}

// TestZapHTTPListener_ServesSameHandler boots the ZAP-HTTP listener
// against a fake handler, fires a request through the zap-proto/http
// client, and verifies the body matches what the same handler would
// produce on plain HTTP. This is the load-bearing contract: a request
// that arrives over ZAP-HTTP MUST reach the same handler with the same
// shape as a request that arrives over HTTP.
func TestZapHTTPListener_ServesSameHandler(t *testing.T) {
	resetZapHTTPListenerForTest()
	defer resetZapHTTPListenerForTest()

	// Handler echoes method + path + Authorization header + body. This
	// mirrors what the gateway middleware chain ultimately sees.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Method", r.Method)
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "method=%s path=%s auth=%s body=%s",
			r.Method, r.URL.Path, r.Header.Get("Authorization"), string(body))
	})

	addr := freePort(t)
	t.Setenv(envZapHTTPListen, addr)
	startZapHTTPListenerOnce(logging.NoOp, handler)
	waitForTCP(t, addr, 2*time.Second)

	body := strings.NewReader(`{"hello":"world"}`)
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/iam/whoami", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer eyJhbGciOi...")

	resp, err := zaphttp.NewTransport(addr).RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	want := `method=POST path=/v1/iam/whoami auth=Bearer eyJhbGciOi... body={"hello":"world"}`
	if string(got) != want {
		t.Errorf("body=%q\nwant=%q", string(got), want)
	}
	if resp.Header.Get("X-Echo-Method") != http.MethodPost {
		t.Errorf("X-Echo-Method=%q want POST", resp.Header.Get("X-Echo-Method"))
	}
	if resp.Header.Get("X-Echo-Path") != "/v1/iam/whoami" {
		t.Errorf("X-Echo-Path=%q want /v1/iam/whoami", resp.Header.Get("X-Echo-Path"))
	}
}

// TestZapHTTPListener_DisabledByEnv verifies that KRAKEND_ZAP_LISTEN=off
// is a hard kill switch — no listener is bound, no port is consumed.
func TestZapHTTPListener_DisabledByEnv(t *testing.T) {
	resetZapHTTPListenerForTest()
	defer resetZapHTTPListenerForTest()

	t.Setenv(envZapHTTPListen, "off")
	startZapHTTPListenerOnce(logging.NoOp, http.NotFoundHandler())

	if defaultZapHTTPState.server.Load() != nil {
		t.Fatal("server should not have been created when KRAKEND_ZAP_LISTEN=off")
	}
}
