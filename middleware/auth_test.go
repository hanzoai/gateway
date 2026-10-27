// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package middleware_test

// The middleware package is the trust boundary of the unified cloud binary
// (HIP-0106 / HIP-0026): StripIdentityHeaders removes client-supplied
// identity headers and Auth decides who may write them. It had no tests.
// These pin the contract through zip's in-process test transport: the strip
// removes every spoofable header, a gateway-written request is trusted
// without calling the verifier, a bearer is verified and re-written in the
// gateway shape, every failure mode is a 401, and - the composition that
// makes the boundary hold - a client that spoofs X-Org-Id against a service
// running Strip then Auth cannot get in, with or without a valid token.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zap-proto/zip"

	gateway "github.com/hanzoai/gateway/v2"
	"github.com/hanzoai/gateway/v2/middleware"
)

// recorder is an AuthVerifier that counts calls and returns a fixed result.
type recorder struct {
	calls int
	id    middleware.Identity
	err   error
}

func (r *recorder) Verify(_ context.Context, _ string) (middleware.Identity, error) {
	r.calls++
	return r.id, r.err
}

var spoofHeaders = []string{
	"X-Org-Id", "X-User-Id", "X-User-Email", "X-User-IsAdmin", "X-Roles", "X-User-Permissions",
}

// do issues req through an app mounting the given middleware ahead of a
// probe handler that records what the chain let through.
func do(t *testing.T, req *http.Request, chain ...zip.Handler) (int, *probe) {
	t.Helper()
	p := &probe{}
	app := zip.New(zip.Config{AppName: "middleware-test", DisableStartupMessage: true})
	app.Raw("GET", "/probe", append(chain, p.serve)...)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("test transport: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, p
}

// probe records the request state the chain delivered to the handler.
type probe struct {
	org, user, email, isAdmin, roles, perms string
	gatewayWritten                          bool
}

func (p *probe) serve(c *zip.Ctx) error {
	p.org = c.Org()
	p.user = c.User()
	p.email = c.UserEmail()
	p.isAdmin = c.Header("X-User-IsAdmin")
	p.roles = c.Header("X-Roles")
	p.perms = c.Header("X-User-Permissions")
	p.gatewayWritten = gateway.AssertGatewayWritten(c)
	return c.Fiber().SendString("ok")
}

func get(path string) *http.Request { return httptest.NewRequest("GET", path, nil) }

// Strip removes every client-supplied identity header.
func TestStrip_RemovesSpoofedIdentityHeaders(t *testing.T) {
	req := get("/probe")
	for _, h := range spoofHeaders {
		req.Header.Set(h, "spoofed")
	}
	code, p := do(t, req, middleware.StripIdentityHeaders())
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	for h, got := range map[string]string{
		"X-Org-Id": p.org, "X-User-Id": p.user, "X-User-Email": p.email,
		"X-User-IsAdmin": p.isAdmin, "X-Roles": p.roles, "X-User-Permissions": p.perms,
	} {
		if got != "" {
			t.Errorf("%s reached the handler as %q after Strip", h, got)
		}
	}
}

// A request already carrying gateway-written identity headers is trusted:
// the verifier is not consulted and the request is marked gateway-written.
func TestAuth_TrustsGatewayWrittenHeaders(t *testing.T) {
	v := &recorder{err: errors.New("must not be called")}
	req := get("/probe")
	req.Header.Set("X-Org-Id", "acme")
	req.Header.Set("X-User-Id", "alice")
	code, p := do(t, req, middleware.Auth(v))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if v.calls != 0 {
		t.Errorf("verifier called %d times on a gateway-written request", v.calls)
	}
	if !p.gatewayWritten {
		t.Error("trusted request not marked gateway-written")
	}
	if p.org != "acme" || p.user != "alice" {
		t.Errorf("identity = %q/%q, want acme/alice", p.org, p.user)
	}
}

// A bearer is verified and re-written in the gateway's header shape.
func TestAuth_VerifiesBearerAndWritesGatewayShape(t *testing.T) {
	v := &recorder{id: middleware.Identity{
		Org: "acme", User: "alice", UserEmail: "a@acme.test", IsAdmin: true,
		Roles: []string{"admin", "dev"},
	}}
	req := get("/probe")
	req.Header.Set("Authorization", "Bearer good-token")
	code, p := do(t, req, middleware.Auth(v))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if v.calls != 1 {
		t.Fatalf("verifier called %d times, want 1", v.calls)
	}
	if p.org != "acme" || p.user != "alice" || p.email != "a@acme.test" {
		t.Errorf("identity = %q/%q/%q", p.org, p.user, p.email)
	}
	if p.isAdmin != "true" {
		t.Errorf("X-User-IsAdmin = %q, want true", p.isAdmin)
	}
	if p.roles != "admin,dev" {
		t.Errorf("X-Roles = %q, want admin,dev", p.roles)
	}
	if !p.gatewayWritten {
		t.Error("verified request not marked gateway-written")
	}
}

// A non-admin identity does not get an admin header at all.
func TestAuth_NonAdminGetsNoAdminHeader(t *testing.T) {
	v := &recorder{id: middleware.Identity{Org: "acme", User: "alice"}}
	req := get("/probe")
	req.Header.Set("Authorization", "Bearer good-token")
	code, p := do(t, req, middleware.Auth(v))
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	if p.isAdmin != "" {
		t.Errorf("X-User-IsAdmin = %q for a non-admin identity", p.isAdmin)
	}
}

// Every failure mode is a 401: no credentials, a non-Bearer scheme, a
// verifier error, and a bearer when no verifier is configured.
func TestAuth_Refusals(t *testing.T) {
	good := &recorder{id: middleware.Identity{Org: "acme", User: "alice"}}
	failing := &recorder{err: errors.New("bad token")}
	cases := []struct {
		name     string
		verifier middleware.AuthVerifier
		header   string
	}{
		{"no credentials", good, ""},
		{"non-bearer scheme", good, "Basic abc"},
		{"verifier error", failing, "Bearer bad-token"},
		{"no verifier configured", nil, "Bearer good-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := get("/probe")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			code, _ := do(t, req, middleware.Auth(tc.verifier))
			if code != 401 {
				t.Errorf("status = %d, want 401", code)
			}
		})
	}
}

// The composition that makes the boundary hold: Strip then Auth. A spoofed
// X-Org-Id alone is stripped and the request falls to a 401; a spoofed
// X-Org-Id with a valid token is replaced by the verified identity, not
// trusted.
func TestStripThenAuth_ClientCannotSpoofGatewayHeaders(t *testing.T) {
	v := &recorder{id: middleware.Identity{Org: "acme", User: "alice"}}

	// Spoofed header, no token: the strip leaves nothing to trust.
	req := get("/probe")
	req.Header.Set("X-Org-Id", "evil")
	code, _ := do(t, req, middleware.StripIdentityHeaders(), middleware.Auth(v))
	if code != 401 {
		t.Errorf("spoofed X-Org-Id without token: status = %d, want 401", code)
	}

	// Spoofed header WITH a token: the verified identity wins.
	req = get("/probe")
	req.Header.Set("X-Org-Id", "evil")
	req.Header.Set("Authorization", "Bearer good-token")
	code, p := do(t, req, middleware.StripIdentityHeaders(), middleware.Auth(v))
	if code != 200 {
		t.Fatalf("valid token after strip: status = %d, want 200", code)
	}
	if p.org != "acme" {
		t.Errorf("org = %q after verification, want acme (the spoof must not survive)", p.org)
	}
}

// Pin the documented trust condition: either gateway header alone flips the
// trust branch (the OR in Auth), which is why Strip must run in front of any
// service not behind the gateway.
func TestAuth_UserHeaderAloneIsTrusted(t *testing.T) {
	v := &recorder{err: errors.New("must not be called")}
	req := get("/probe")
	req.Header.Set("X-User-Id", "alice")
	code, _ := do(t, req, middleware.Auth(v))
	if code != 200 {
		t.Fatalf("status = %d, want 200 (X-User-Id alone is trusted)", code)
	}
	if v.calls != 0 {
		t.Errorf("verifier called %d times", v.calls)
	}
}
