package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCORSPreflight_BrandAllowlist verifies that corsPreflightMiddleware
// answers OPTIONS preflight for any Hanzo/Lux/Zoo/Pars property (and its
// subdomains) using the SAME baked-in allowlist as the widget security
// middleware (defaultAllowedOrigins), without any per-origin env config.
//
// This is the fix for browser SPAs (e.g. https://cowork.hanzo.ai) whose
// AI calls to /v1/chat/completions previously failed "Failed to fetch"
// because the preflight returned no Access-Control-Allow-Origin.
func TestCORSPreflight_BrandAllowlist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name    string
		origin  string
		allowed bool
	}{
		// Subdomain of a baked-in brand domain — the cowork case.
		{"cowork.hanzo.ai subdomain", "https://cowork.hanzo.ai", true},
		// Apex brand domain.
		{"hanzo.app apex", "https://hanzo.app", true},
		// Other brand properties via suffix match.
		{"hanzo.chat", "https://hanzo.chat", true},
		{"lux.network subdomain", "https://app.lux.network", true},
		{"zoo.ngo apex", "https://zoo.ngo", true},
		// Karma (external customer) — apex + any subdomain both resolve from the
		// single "karma.style" allowlist entry (suffix match, like the cowork case).
		{"karma.style apex", "https://karma.style", true},
		{"tryon.karma.style subdomain", "https://tryon.karma.style", true},
		// Localhost default (dev).
		{"localhost:3000 default", "http://localhost:3000", true},
		// Not on any allowlist.
		{"evil.com denied", "https://evil.com", false},
		{"look-alike suffix denied", "https://nothanzo.ai", false},
		{"empty origin ignored", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)
			r.Use(corsPreflightMiddleware())
			// Downstream handler returns 200 if the preflight was NOT
			// short-circuited by the middleware (i.e. origin not allowed).
			r.OPTIONS("/v1/chat/completions", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
			req.Host = "api.hanzo.ai"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			req.Header.Set("Access-Control-Request-Method", "POST")

			r.ServeHTTP(w, req)

			acao := w.Header().Get("Access-Control-Allow-Origin")
			if tc.allowed {
				if w.Code != http.StatusNoContent {
					t.Fatalf("allowed origin %q: expected 204, got %d", tc.origin, w.Code)
				}
				if acao != tc.origin {
					t.Fatalf("allowed origin %q: expected ACAO=%q, got %q", tc.origin, tc.origin, acao)
				}
				if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
					t.Fatalf("allowed origin %q: expected ACA-Credentials=true, got %q", tc.origin, got)
				}
				if got := w.Header().Get("Access-Control-Allow-Methods"); got == "" {
					t.Fatalf("allowed origin %q: expected ACA-Methods set", tc.origin)
				}
			} else {
				// Denied: preflight falls through to the handler (200) and
				// MUST NOT carry an Access-Control-Allow-Origin header.
				if acao != "" {
					t.Fatalf("denied origin %q: expected no ACAO, got %q", tc.origin, acao)
				}
				if w.Code != http.StatusOK {
					t.Fatalf("denied origin %q: expected fall-through 200, got %d", tc.origin, w.Code)
				}
			}
		})
	}
}

// TestCORSPreflight_EnvOriginStillHonored verifies that an explicit
// fully-qualified origin supplied via GATEWAY_CORS_ORIGINS is still allowed
// alongside the brand allowlist (additive, no regression).
func TestCORSPreflight_EnvOriginStillHonored(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("GATEWAY_CORS_ORIGINS", "https://partner.example.com")

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.Use(corsPreflightMiddleware())
	r.OPTIONS("/v1/chat/completions", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	req.Header.Set("Origin", "https://partner.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("env origin: expected 204, got %d", w.Code)
	}
	if acao := w.Header().Get("Access-Control-Allow-Origin"); acao != "https://partner.example.com" {
		t.Fatalf("env origin: expected ACAO echo, got %q", acao)
	}
}
