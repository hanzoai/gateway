// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hanzoai/cloud"
	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"
)

// TestMount_ServesHealth asserts Mount (1) installs without a routes file —
// co-resident subsystems own their own routes in cloud-mode — and (2) mounts
// a native zip /_/gateway/healthz endpoint answering 200 + JSON.
//
// This test was previously gated behind `//go:build cloud` and asserted
// registration into `cloud.Registry`. Cloud replaced that global registry with
// an explicit composition root (cloud/apps.Wire), so the symbol no longer
// exists and the file stopped compiling — leaving Mount, the HIP-0106 embed
// surface, with zero coverage. mount.go carries no build tag, so neither does
// its test: the mount surface is now exercised by the default `go test ./...`.
func TestMount_ServesHealth(t *testing.T) {
	// Force AUTH_ENABLED off: validating JWTs against a real JWKS URL would
	// require network. The strip-list is exercised by
	// auth_middleware_security_test.go at the gateway root.
	t.Setenv("AUTH_ENABLED", "false")
	// Ensure no routes file is referenced.
	_ = os.Unsetenv("GATEWAY_ROUTES_FILE")

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

// TestZipFromGin_DoesNotReflectRequestHeadersOntoResponse is the regression
// guard for the credential-reflection defect fixed in zipFromGin.
//
// The NoRoute shim used to copy every inbound request header onto
// c.Writer.Header() — the RESPONSE — while its comment claimed it was copying
// them onto the downstream request. That echoed Authorization, Cookie and the
// gateway-minted identity set (X-Org-Id / X-User-Id / X-User-Email) straight
// back to the caller, exposing them to anything that observes or caches
// response headers. The copy was also dead for its stated purpose: the
// downstream reads c.Request, which the gin handler already mutated in place.
//
// Contract: nothing the client sent, and nothing the gateway minted onto the
// request, may appear in the response headers.
func TestZipFromGin_DoesNotReflectRequestHeadersOntoResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	app := zip.New(zip.Config{Logger: luxlog.New("test")})
	// Mint an identity header onto the REQUEST, exactly as the real auth
	// middleware does after validating a JWT.
	app.Use(zipFromGin(func(c *gin.Context) {
		c.Request.Header.Set("X-Org-Id", "acme")
		c.Request.Header.Set("X-User-Id", "user-1")
	}))
	app.Get("/echo", func(c *zip.Ctx) error {
		return c.String(200, "ok")
	})

	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("Authorization", "Bearer super-secret-jwt")
	req.Header.Set("Cookie", "session=top-secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}

	// Client-supplied credentials must never be reflected.
	for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-For"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("request header %q reflected onto response: %q", h, got)
		}
	}
	// Gateway-minted identity headers are for the downstream only.
	for _, h := range []string{"X-Org-Id", "X-User-Id"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("minted identity header %q leaked onto response: %q", h, got)
		}
	}

	// And the downstream still observes the minted headers (the shim must
	// not have broken the thing the copy was mistakenly trying to do).
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body: got %q want %q", string(body), "ok")
	}
}

// TestZipFromGin_PropagatesMintedHeadersDownstream pins the behaviour the
// deleted copy loop was nominally for: a header the gin middleware sets on
// c.Request MUST be visible to the downstream zip handler.
func TestZipFromGin_PropagatesMintedHeadersDownstream(t *testing.T) {
	gin.SetMode(gin.TestMode)

	app := zip.New(zip.Config{Logger: luxlog.New("test")})
	app.Use(zipFromGin(func(c *gin.Context) {
		c.Request.Header.Set("X-Org-Id", "acme")
	}))
	app.Get("/who", func(c *zip.Ctx) error {
		return c.String(200, c.Header("X-Org-Id"))
	})

	req := httptest.NewRequest("GET", "/who", nil)
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "acme" {
		t.Fatalf("downstream X-Org-Id: got %q want %q", string(body), "acme")
	}
}
