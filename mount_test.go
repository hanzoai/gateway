// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hanzoai/authz"
	luxlog "github.com/luxfi/log"

	"github.com/zap-proto/zip"
)

// mountApp builds a mounted gateway app with auth off — the shape a co-resident
// cloud binary has when the deployment does not front it with IAM.
func mountApp(t *testing.T) *zip.App {
	t.Helper()
	t.Setenv("AUTH_ENABLED", "false")
	_ = os.Unsetenv("GATEWAY_ROUTES_FILE")
	app := zip.New(zip.Config{Logger: luxlog.New("test"), AppName: "gateway"})
	deps := MountDeps{
		Logger: luxlog.New("test"),
		Brand:  "hanzo",
		Domain: "api.hanzo.ai",
	}
	if err := Mount(app, deps); err != nil {
		t.Fatalf("Mount: %v", err)
	}
	return app
}

// TestMount_ServesProbes asserts Mount (1) installs without a routes file —
// co-resident subsystems own their own routes in cloud-mode — and (2) serves
// the typed probe pair under the subsystem's reserved prefix.
func TestMount_ServesProbes(t *testing.T) {
	app := mountApp(t)

	for path, want := range map[string]string{
		"/_/gateway/healthz": "ok",
		"/_/gateway/readyz":  "ready",
	} {
		resp, err := app.Fiber().Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("%s status: got %d want 200", path, resp.StatusCode)
		}
		var out ProbeOut
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("%s decode: %v", path, err)
		}
		if out.Status != want || out.Service != ServiceName {
			t.Fatalf("%s: got %+v, want status=%q service=%q", path, out, want, ServiceName)
		}
	}
}

// TestMount_ProbesAreTypedOps is the anti-DARK-ROUTE assertion for the mount.
//
// A route registered with app.Get(path, func(c *zip.Ctx) error) appends NOTHING
// to the op registry, so it is in no OpenAPI document, no MCP tool list, no CLI
// and no generated SDK — and nothing about a green build says so. This pins the
// two facts that would otherwise drift apart silently: the number of routes the
// live router holds, and the number of them that are typed ops.
func TestMount_ProbesAreTypedOps(t *testing.T) {
	d := mountApp(t).Declaration()

	const wantRoutes, wantOps = 2, 2
	if len(d.Routes) != wantRoutes {
		t.Errorf("mounted routes: got %d want %d — %+v", len(d.Routes), wantRoutes, d.Routes)
	}
	if len(d.Ops) != wantOps {
		t.Errorf("typed ops: got %d want %d — %+v", len(d.Ops), wantOps, d.Ops)
	}
	for _, r := range d.Routes {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method on the mount surface: %s %s", r.Method, r.Pattern)
		}
	}
}

// TestZipAuth_StripSurvives is the regression guard for the defect the native
// boundary fixes, and it is a REAL one: the gin bridge this replaced did not
// strip anything.
//
// zipFromGin ran the middleware through fiber's net/http adaptor, whose
// copy-back loop writes the middleware's headers onto the fasthttp request with
// Set and NEVER Del. A header the strip DELETED was therefore restored from the
// original request, so a client-supplied X-User-IsAdmin / X-Org-Id /
// X-User-Permissions reached the downstream subsystem intact — through the one
// piece of code whose entire job is to remove it.
//
// The gate runs with auth DISABLED here on purpose: the strip is unconditional,
// it is the first thing the policy does on every route class, and it must hold
// even in the dev/test topology where nothing is validated.
func TestZipAuth_StripSurvives(t *testing.T) {
	app := mountApp(t)

	seen := map[string]string{}
	app.Get("/echo", func(c *zip.Ctx) error {
		for _, h := range append(append([]string{}, authz.Headers...), authz.Retired...) {
			if v := c.Header(h); v != "" {
				seen[h] = v
			}
		}
		// The vendor-prefix backstop is part of the same one strip.
		if v := c.Header("X-Hanzo-Smuggled"); v != "" {
			seen["X-Hanzo-Smuggled"] = v
		}
		// A header that is NOT identity must be untouched — the boundary strips
		// authority, it does not sanitise the request.
		return c.String(200, c.Header("X-Trace-Id"))
	})

	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("X-User-IsAdmin", "true")
	req.Header.Set("X-Org-Id", "victim-org")
	req.Header.Set("X-User-Id", "attacker")
	req.Header.Set("X-User-Permissions", "9223372036854775807")
	req.Header.Set("X-Hanzo-Smuggled", "yes")
	req.Header.Set("X-Trace-Id", "keep-me")

	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("SECURITY: client-supplied identity survived the trust boundary: %v", seen)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "keep-me" {
		t.Fatalf("non-identity header was disturbed: got %q want %q", string(body), "keep-me")
	}
}

// TestZipAuth_WritesValidatedIdentityDownstream pins the other half of the
// boundary: what a VERIFIED token earns is written onto the request the
// downstream reads, natively, with no copy-back step to lose it.
func TestZipAuth_WritesValidatedIdentityDownstream(t *testing.T) {
	tj := newTestJWKS(t)
	jwks := tj.serveJWKS(t)
	defer jwks.Close()

	app := zip.New(zip.Config{Logger: luxlog.New("test"), AppName: "gateway"})
	app.Use(zipAuth(edgeAuthConfig(jwks.URL)))

	var org, user, email string
	app.Get("/x", func(c *zip.Ctx) error {
		org, user, email = c.Header(authz.HeaderOrg), c.Header(authz.HeaderUser), c.Header(authz.HeaderUserEmail)
		return c.String(200, "ok")
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+tj.signToken(t, memberToken()))
	// A forged org alongside a real token: the selection is an INTENT, admitted
	// only where the signed membership set admits it. "victim-org" is not in it.
	req.Header.Set("X-Org-Id", "victim-org")

	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if org != "hanzo" {
		t.Errorf("X-Org-Id: got %q want %q (a forged selection must not be honoured)", org, "hanzo")
	}
	if user == "" || user == "attacker" {
		t.Errorf("X-User-Id: got %q, want the token's subject", user)
	}
	if email != "alice@hanzo.ai" {
		t.Errorf("X-User-Email: got %q want %q", email, "alice@hanzo.ai")
	}
}

// TestZipAuth_DoesNotReflectRequestHeadersOntoResponse keeps the guard the
// deleted bridge carried: nothing the client sent, and nothing the gateway
// wrote onto the request, may appear in the RESPONSE headers, where anything
// that observes or caches them would see credentials.
func TestZipAuth_DoesNotReflectRequestHeadersOntoResponse(t *testing.T) {
	app := mountApp(t)
	app.Get("/echo", func(c *zip.Ctx) error { return c.String(200, "ok") })

	req := httptest.NewRequest("GET", "/echo", nil)
	req.Header.Set("Authorization", "Bearer super-secret-jwt")
	req.Header.Set("Cookie", "session=top-secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("X-Org-Id", "acme")

	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("Fiber Test: %v", err)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Forwarded-For", "X-Org-Id", "X-User-Id"} {
		if got := resp.Header.Get(h); got != "" {
			t.Errorf("request header %q reflected onto response: %q", h, got)
		}
	}
}

// TestMount_GatesAreOnTheChainMountInstalls is the anti-DARK-EDGE assertion, and
// it is the one this repo needed: a gate can exist, be tested, and pass every
// test that drives it DIRECTLY, while the mount that production runs never
// installs it. That is exactly the state the widget gate and the CORS policy
// were in — both fully tested through gin, neither reachable on the zip edge.
//
// So this drives the app gateway.Mount BUILT. If a future edit drops a Use, the
// gate stops answering here and this fails; a test that assembled its own
// zip.App would keep passing while the boundary went dark.
func TestMount_GatesAreOnTheChainMountInstalls(t *testing.T) {
	// Auth is off in mountApp (the co-resident dev topology), which is the
	// harder case on purpose: these two gates must hold even when nothing is
	// validating tokens, because neither of them is an authn gate.
	app := mountApp(t)
	app.Get("/v1/chat/completions", func(c *zip.Ctx) error { return c.String(http.StatusOK, "ok") })

	t.Run("cors_preflight_is_answered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Origin", "https://hanzo.ai")
		req.Header.Set("Access-Control-Request-Headers", "content-type, x-idempotency-key")
		resp, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("Fiber Test: %v", err)
		}
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight: got %d want 204 — the mount installs no CORS", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://hanzo.ai" {
			t.Errorf("Access-Control-Allow-Origin: got %q want the reflected origin", got)
		}
		if !strings.Contains(resp.Header.Get("Vary"), "Origin") {
			t.Error("a reflected origin without Vary: Origin lets a shared cache cross tenants")
		}
		// The header the browser asked about must come back, or it cannot send it and
		// the call dies at the preflight with nothing on this side to see.
		if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "content-type, x-idempotency-key" {
			t.Errorf("Access-Control-Allow-Headers: got %q want the asked-for names", got)
		}
	})

	t.Run("foreign_origin_earns_no_cors", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Origin", "https://evil.example")
		resp, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("Fiber Test: %v", err)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("a non-allowlisted origin was reflected: %q", got)
		}
	})

	t.Run("widget_key_needs_an_allowlisted_origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Authorization", "Bearer hz_widget_public")
		req.Header.Set("Origin", "https://evil.example")
		resp, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("Fiber Test: %v", err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("widget key from a foreign origin: got %d want 403 — the mount installs no widget gate",
				resp.StatusCode)
		}
	})

	t.Run("server_to_server_key_is_untouched", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Authorization", "Bearer hk-server-side")
		resp, err := app.Fiber().Test(req)
		if err != nil {
			t.Fatalf("Fiber Test: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("non-widget credential: got %d want 200 — the widget gate acts on hz_ only",
				resp.StatusCode)
		}
	})
}
