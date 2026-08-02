// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hanzoai/authz"
	"github.com/hanzoai/cloud"
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
	deps := cloud.Deps{
		Logger:  luxlog.New("test"),
		Brand:   "hanzo",
		Domain:  "api.hanzo.ai",
		DataDir: t.TempDir(),
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
	app.Use(zipAuth(zipTestAuthConfig(jwks.URL)))

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

// TestBothTransportsAdmitAlike is why the policy is a value.
//
// The gateway has two HTTP edges — the legacy Lura engine on gin (the shipping
// image) and the native zip mount (the unified cloud binary) — and for as long
// as the ALLOW/DENY ladder was written out inside a gin closure, the second one
// could only reach it through an adapter. Two edges that answer differently
// about one request is the whole failure mode. They now share [authGate.admit],
// and this asserts it on the cases that distinguish the classes: refuse,
// tokenless, public path, public host, ingest, API key, valid token.
func TestBothTransportsAdmitAlike(t *testing.T) {
	tj := newTestJWKS(t)
	jwks := tj.serveJWKS(t)
	defer jwks.Close()
	cfg := zipTestAuthConfig(jwks.URL)
	valid := "Bearer " + tj.signToken(t, memberToken())

	cases := []struct {
		name   string
		method string
		host   string
		path   string
		auth   string
		want   int
	}{
		{"tokenless_refused", "GET", "api.hanzo.ai", "/v1/chat/completions", "", 401},
		{"garbage_token_refused", "GET", "api.hanzo.ai", "/v1/chat/completions", "Bearer not-a-jwt", 401},
		{"public_path", "GET", "api.hanzo.ai", "/healthz", "", 200},
		{"public_host", "GET", "hanzo.id", "/v1/anything", "", 200},
		{"ingest_class", "POST", "api.hanzo.ai", "/v1/sentry/proj/envelope/", "", 200},
		{"ingest_read_is_gated", "GET", "api.hanzo.ai", "/v1/sentry/proj/issues", "", 401},
		{"api_key", "GET", "api.hanzo.ai", "/v1/chat/completions", "Bearer sk-live-abcdef", 200},
		{"valid_jwt", "GET", "api.hanzo.ai", "/v1/chat/completions", valid, 200},
	}

	gin.SetMode(gin.TestMode)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := gin.New()
			g.Use(NewAuthMiddleware(cfg))
			g.Handle(tc.method, tc.path, func(c *gin.Context) { c.Status(200) })
			gr := httptest.NewRequest(tc.method, tc.path, nil)
			gr.Host = tc.host
			if tc.auth != "" {
				gr.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			g.ServeHTTP(w, gr)

			z := zip.New(zip.Config{Logger: luxlog.New("test"), AppName: "gateway"})
			z.Use(zipAuth(cfg))
			z.All(tc.path, func(c *zip.Ctx) error { return c.String(200, "") })
			zr := httptest.NewRequest(tc.method, tc.path, nil)
			zr.Host = tc.host
			if tc.auth != "" {
				zr.Header.Set("Authorization", tc.auth)
			}
			zresp, err := z.Fiber().Test(zr)
			if err != nil {
				t.Fatalf("zip: %v", err)
			}

			if w.Code != tc.want {
				t.Errorf("gin: got %d want %d (%s)", w.Code, tc.want, w.Body.String())
			}
			if zresp.StatusCode != tc.want {
				body, _ := io.ReadAll(zresp.Body)
				t.Errorf("zip: got %d want %d (%s)", zresp.StatusCode, tc.want, body)
			}
			if w.Code != zresp.StatusCode {
				t.Errorf("TRANSPORTS DISAGREE: gin=%d zip=%d", w.Code, zresp.StatusCode)
			}
		})
	}
}

// zipTestAuthConfig is the auth config both transports are driven with above:
// one JWKS, one issuer, one audience allowlist, no billing, auth REQUIRED (so a
// tokenless request is a refusal rather than an anonymous pass-through).
func zipTestAuthConfig(jwksURL string) AuthConfig {
	return AuthConfig{
		Enabled:        true,
		JWKSURL:        jwksURL,
		Issuer:         "https://hanzo.id",
		Audiences:      []string{"https://api.hanzo.ai"},
		BillingEnabled: false,
		PublicPaths:    []string{"/healthz"},
		PublicHosts:    []string{"hanzo.id"},
		RequireAuth:    true,
	}
}

// memberToken is the shape every user token IAM signs has: an owner AND the
// signed membership set, which is the only thing that confers an org. A fixture
// without `orgs` is a token that cannot exist (see validClaims).
func memberToken() map[string]any {
	return iamToken("hanzo", map[string]any{
		"orgs": []map[string]any{{"org": "hanzo", "role": "member"}},
	})
}
