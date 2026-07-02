// Copyright © 2026 Hanzo AI. MIT License.

//go:build cloud
// +build cloud

package gateway

import (
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hanzoai/cloud"
	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"
)

// TestMount_RegistersHealthAndRegistry asserts the gateway subsystem
// (1) registers itself in cloud.Registry via init(), (2) mounts a native
// zip /_/gateway/healthz endpoint that answers 200 + JSON, and (3) does
// not refuse to start when no GATEWAY_ROUTES_FILE is configured —
// co-resident subsystems own their own routes in cloud-mode.
func TestMount_RegistersHealthAndRegistry(t *testing.T) {
	// Force AUTH_ENABLED off in the test: validating JWTs against a real
	// JWKS URL would require network. The strip-list is exercised by
	// auth_middleware_security_test.go at the gateway root.
	t.Setenv("AUTH_ENABLED", "false")
	// Ensure no routes file is referenced.
	_ = os.Unsetenv("GATEWAY_ROUTES_FILE")

	if !registryContains("gateway") {
		t.Fatalf("cloud.Registry missing 'gateway'; Names=%v", registryNames())
	}

	app := zip.New(zip.Config{Logger: luxlog.New("test")})
	deps := cloud.Deps{
		Logger:  luxlog.New("test"),
		Brand:   "hanzo",
		Domain:  "api.hanzo.ai",
		DataDir: t.TempDir(),
	}
	if err := Mount(app, deps); err != nil {
		t.Fatalf("Mount: %v", err)
	}

	req := httptest.NewRequest("GET", "/_/gateway/healthz", nil)
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(raw), `"service":"gateway"`) {
		t.Fatalf("body: got %q, want service=gateway", string(raw))
	}
}

func registryContains(name string) bool {
	for _, s := range cloud.Registry {
		if s.Name == name {
			return true
		}
	}
	return false
}

func registryNames() []string {
	out := make([]string, 0, len(cloud.Registry))
	for _, s := range cloud.Registry {
		out = append(out, s.Name)
	}
	return out
}
