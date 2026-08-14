// Copyright © 2026 Hanzo AI. Apache-2.0 License.

//go:build legacy
// +build legacy

// transport_parity_test.go is why the policies are values.
//
// The gateway has two HTTP edges — the legacy Lura engine on gin (the shipping
// image) and the native zip mount (the unified cloud binary) — and two edges
// that answer differently about one request is the whole failure mode this
// package's decomplection exists to remove. Each gate is now a framework-free
// value with a transport per edge, and these tests drive one request through
// BOTH and assert they agree.
//
// It is `legacy`-tagged because it is the ONLY build in which both transports
// exist at once. That is also the build the Dockerfile ships, so this runs on
// the gate that guards the image.
package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestBothTransportsAdmitAlike pins the AUTH gate on the cases that distinguish
// its route classes: refuse, tokenless, public path, public host, ingest, API
// key, valid token.
func TestBothTransportsAdmitAlike(t *testing.T) {
	tj := newTestJWKS(t)
	jwks := tj.serveJWKS(t)
	defer jwks.Close()
	cfg := edgeAuthConfig(jwks.URL)
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := map[string]string{}
			if tc.auth != "" {
				hdr["Authorization"] = tc.auth
			}
			g := ginEdge(t, NewAuthMiddleware(cfg), tc.method, tc.path, tc.host, hdr)
			z := zipEdge(t, zipAuth(cfg), tc.method, tc.path, tc.host, hdr)
			assertAlike(t, tc.want, g, z)
		})
	}
}

// TestBothTransportsGateWidgetKeysAlike pins the WIDGET gate. Until the policy
// became a value it had NO zip transport at all, so a widget key — a public
// credential lifted from any page's source — reached the HIP-0106 boundary with
// neither an origin check nor a rate limit.
func TestBothTransportsGateWidgetKeysAlike(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  100,
		GlobalMaxRequests: 1000,
		Window:            time.Minute,
		CleanupInterval:   time.Minute,
		AllowedOrigins:    []string{"hanzo.ai"},
	}

	cases := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"not_a_widget_key_passes", map[string]string{"Authorization": "Bearer sk-server-side"}, 200},
		{"no_credential_passes", nil, 200},
		{"widget_key_allowed_origin", map[string]string{
			"Authorization": "Bearer hz_public", "Origin": "https://hanzo.ai"}, 200},
		{"widget_key_allowed_subdomain", map[string]string{
			"Authorization": "Bearer hz_public", "Origin": "https://cowork.hanzo.ai"}, 200},
		{"widget_key_foreign_origin_refused", map[string]string{
			"Authorization": "Bearer hz_public", "Origin": "https://evil.example"}, 403},
		{"widget_key_no_origin_refused", map[string]string{
			"Authorization": "Bearer hz_public"}, 403},
		{"widget_key_referer_fallback", map[string]string{
			"Authorization": "Bearer hz_public", "Referer": "https://hanzo.ai/app"}, 200},
		// This case used to assert 200 — it ENCODED a bypass. A User-Agent is
		// written by the caller, so "kube-probe" admitted anyone who typed it,
		// and the test's name made it read like a feature. Nothing legitimate
		// regressed by removing it: a kubelet probe carries no Authorization
		// header, so it is already past this gate at the isWidgetKey check.
		{"widget_key_kube_probe_ua_is_not_a_credential", map[string]string{
			"Authorization": "Bearer hz_public", "User-Agent": "kube-probe/1.31"}, 403},
		{"widget_key_wget_ua_is_not_a_credential", map[string]string{
			"Authorization": "Bearer hz_public", "User-Agent": "Wget/1.21"}, 403},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A gate per case: the limiter is stateful, and sharing one across
			// cases would make an origin verdict depend on how many cases ran first.
			g := ginEdge(t, NewWidgetSecurityMiddleware(cfg), "GET", "/v1/chat/completions", "api.hanzo.ai", tc.header)
			z := zipEdge(t, zipWidget(cfg), "GET", "/v1/chat/completions", "api.hanzo.ai", tc.header)
			assertAlike(t, tc.want, g, z)
		})
	}
}

// TestBothTransportsRateLimitWidgetKeysAlike pins the OTHER half of the widget
// gate: the sliding window. One IP, a cap of two, three requests — the third is
// refused on both edges, from one limiter implementation.
func TestBothTransportsRateLimitWidgetKeysAlike(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  2,
		GlobalMaxRequests: 1000,
		Window:            time.Minute,
		CleanupInterval:   time.Minute,
		AllowedOrigins:    []string{"hanzo.ai"},
	}
	hdr := map[string]string{"Authorization": "Bearer hz_public", "Origin": "https://hanzo.ai"}

	ginMW, zipMW := NewWidgetSecurityMiddleware(cfg), zipWidget(cfg)
	for i, want := range []int{200, 200, 429} {
		g := ginEdge(t, ginMW, "GET", "/v1/chat/completions", "api.hanzo.ai", hdr)
		z := zipEdge(t, zipMW, "GET", "/v1/chat/completions", "api.hanzo.ai", hdr)
		t.Run(fmt.Sprintf("request_%d", i+1), func(t *testing.T) { assertAlike(t, want, g, z) })
	}
}

// TestBothTransportsIgnoreForgedForwardedFor pins the rate limit's KEY, which is
// the half of the widget gate that actually binds a scripted attacker. (Origin is
// written by the caller: it constrains a browser, and constrains a script not at
// all. So if the bucket is forgeable, a public hz_ key has no limit.)
//
// This is the case the parity harness could not previously see. Neither edge test
// ever set a forwarded header, so both answered about the same nothing and agreed
// — while in production they disagreed completely:
//
//	gin  ClientIP() trusts X-Forwarded-For from every peer (defaultTrustedCIDRs
//	     is 0.0.0.0/0) and returns the leftmost entry, so a rotating header is a
//	     fresh bucket every request and the cap never trips. Measured on the live
//	     lux-ns edge: 20/20 admitted against a cap of 10.
//	zip  IP() reads no forwarded header at all, so behind ingress every caller
//	     shares the ingress pod's bucket and the cap trips for everyone at once.
//
// Three requests, a cap of two, a DIFFERENT forged X-Forwarded-For on each: the
// third must be refused on both edges, because the forgery buys nothing on either.
func TestBothTransportsIgnoreForgedForwardedFor(t *testing.T) {
	cfg := WidgetSecurityConfig{
		MaxRequestsPerIP:  2,
		GlobalMaxRequests: 1000,
		Window:            time.Minute,
		CleanupInterval:   time.Minute,
		AllowedOrigins:    []string{"hanzo.ai"},
	}

	ginMW, zipMW := NewWidgetSecurityMiddleware(cfg), zipWidget(cfg)
	for i, want := range []int{200, 200, 429} {
		hdr := map[string]string{
			"Authorization":   "Bearer hz_public",
			"Origin":          "https://hanzo.ai",
			"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1),
		}
		g := ginEdge(t, ginMW, "GET", "/v1/chat/completions", "api.hanzo.ai", hdr)
		z := zipEdge(t, zipMW, "GET", "/v1/chat/completions", "api.hanzo.ai", hdr)
		t.Run(fmt.Sprintf("forged_hop_%d", i+1), func(t *testing.T) { assertAlike(t, want, g, z) })
	}
}

// TestBothTransportsAnswerPreflightAlike pins the CORS gate. Same gap as the
// widget one: the zip edge ran no preflight at all, so a browser SPA against the
// unified binary got whatever the router does with an unrouted OPTIONS.
func TestBothTransportsAnswerPreflightAlike(t *testing.T) {
	cases := []struct {
		name   string
		method string
		origin string
		want   int
		acao   string
	}{
		{"preflight_allowed_brand", "OPTIONS", "https://hanzo.ai", 204, "https://hanzo.ai"},
		{"preflight_allowed_subdomain", "OPTIONS", "https://cowork.hanzo.ai", 204, "https://cowork.hanzo.ai"},
		{"preflight_allowed_localhost", "OPTIONS", "http://localhost:3000", 204, "http://localhost:3000"},
		{"preflight_foreign_origin_gets_nothing", "OPTIONS", "https://evil.example", 200, ""},
		{"simple_request_allowed_origin", "GET", "https://hanzo.ai", 200, "https://hanzo.ai"},
		{"simple_request_no_origin", "GET", "", 200, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdr := map[string]string{}
			if tc.origin != "" {
				hdr["Origin"] = tc.origin
			}
			g := ginEdge(t, corsPreflightMiddleware(), tc.method, "/v1/chat/completions", "api.hanzo.ai", hdr)
			z := zipEdge(t, zipCORS(newCORSPolicy()), tc.method, "/v1/chat/completions", "api.hanzo.ai", hdr)
			assertAlike(t, tc.want, g, z)

			if g.acao != tc.acao {
				t.Errorf("gin Access-Control-Allow-Origin: got %q want %q", g.acao, tc.acao)
			}
			if z.acao != tc.acao {
				t.Errorf("zip Access-Control-Allow-Origin: got %q want %q", z.acao, tc.acao)
			}
			// Credentialed reflection is only ever safe WITH Vary: Origin — a
			// shared cache must never hand one origin's ACAO to another.
			if tc.acao != "" {
				for _, e := range []edgeResult{g, z} {
					if e.credentials != "true" || !strings.Contains(e.vary, "Origin") {
						t.Errorf("%s: reflected an origin without the credentials+Vary pair: %+v", e.name, e)
					}
				}
			}
		})
	}
}

// ginEdge runs one request through a gin middleware and reports the answer.
func ginEdge(t *testing.T, mw gin.HandlerFunc, method, path, host string, hdr map[string]string) edgeResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.Use(mw)
	g.Handle(method, path, func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	return edgeResult{
		name:        "gin",
		status:      w.Code,
		acao:        w.Header().Get("Access-Control-Allow-Origin"),
		credentials: w.Header().Get("Access-Control-Allow-Credentials"),
		vary:        w.Header().Get("Vary"),
	}
}

// assertAlike is the whole point: each edge must answer what the policy says,
// and — separately asserted, because it is the failure that matters — they must
// answer the SAME thing.
func assertAlike(t *testing.T, want int, got ...edgeResult) {
	t.Helper()
	for _, e := range got {
		if e.status != want {
			t.Errorf("%s: got %d want %d", e.name, e.status, want)
		}
	}
	for _, e := range got[1:] {
		if e.status != got[0].status {
			t.Errorf("TRANSPORTS DISAGREE: %s=%d %s=%d", got[0].name, got[0].status, e.name, e.status)
		}
	}
}
