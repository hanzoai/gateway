// Copyright © 2026 Hanzo AI. MIT License.

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestCORSRecoveryHandler_F3 is the Great-Audit F3 regression. The gateway's
// panic-recovery handler must never turn a 500 into a
// wildcard-reflect-with-credentials primitive: an allowlisted Origin is
// reflected with Access-Control-Allow-Credentials so the browser sees the real
// error (not a CORS failure), but ANY other Origin — including an attacker's —
// gets NO Access-Control-Allow-Origin / -Credentials on the error response, so
// no site can make a credentialed cross-origin read against a session when the
// app 5xxs.
//
// gin.CustomRecovery(corsRecoveryHandler(newCORSOriginAllower())) is the exact
// wiring the legacy engine installs in NewEngine (krakend_engine.go), so this
// exercises the real handler.
func TestCORSRecoveryHandler_F3(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(gin.CustomRecovery(corsRecoveryHandler(newCORSOriginAllower())))
		r.GET("/boom", func(c *gin.Context) { panic("kaboom") })
		return r
	}

	cases := []struct {
		name    string
		origin  string
		reflect bool // expect Origin reflected + credentials on the 500
	}{
		{"evil origin not reflected", "https://evil.com", false},
		{"look-alike suffix not reflected", "https://nothanzo.ai", false},
		{"brand apex reflected", "https://hanzo.ai", true},
		{"brand subdomain reflected", "https://cowork.hanzo.ai", true},
		{"lux subdomain reflected", "https://app.lux.network", true},
		{"zoo apex reflected", "https://zoo.ngo", true},
		{"localhost dev reflected", "http://localhost:3000", true},
		{"no origin no cors", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/boom", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			newRouter().ServeHTTP(w, req)

			// Recovery always returns 500 regardless of origin.
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("origin %q: expected 500 from recovery, got %d", tc.origin, w.Code)
			}

			acao := w.Header().Get("Access-Control-Allow-Origin")
			acac := w.Header().Get("Access-Control-Allow-Credentials")
			if tc.reflect {
				if acao != tc.origin {
					t.Fatalf("allowlisted origin %q: expected ACAO=%q, got %q", tc.origin, tc.origin, acao)
				}
				if acac != "true" {
					t.Fatalf("allowlisted origin %q: expected ACA-Credentials=true, got %q", tc.origin, acac)
				}
				if v := w.Header().Get("Vary"); v != "Origin" {
					t.Fatalf("allowlisted origin %q: expected Vary=Origin, got %q", tc.origin, v)
				}
			} else {
				// The F3 assertion: a disallowed / absent origin must NEVER get
				// a credentialed CORS reflect on the error path.
				if acao != "" {
					t.Fatalf("disallowed origin %q: expected NO ACAO on 500, got %q", tc.origin, acao)
				}
				if acac != "" {
					t.Fatalf("disallowed origin %q: expected NO ACA-Credentials on 500, got %q", tc.origin, acac)
				}
			}
		})
	}
}

// TestCORSRecoveryHandler_SharesHappyPathAllowlist proves the error path uses
// the SAME allowlist as corsPreflightMiddleware (no drift between the two
// callers of newCORSOriginAllower): an origin added via GATEWAY_CORS_ORIGINS is
// reflected with credentials on a 500 exactly as it is on a preflight.
func TestCORSRecoveryHandler_SharesHappyPathAllowlist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("GATEWAY_CORS_ORIGINS", "https://partner.example.com")

	r := gin.New()
	r.Use(gin.CustomRecovery(corsRecoveryHandler(newCORSOriginAllower())))
	r.GET("/boom", func(c *gin.Context) { panic("kaboom") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	req.Header.Set("Origin", "https://partner.example.com")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if acao := w.Header().Get("Access-Control-Allow-Origin"); acao != "https://partner.example.com" {
		t.Fatalf("env origin: expected ACAO echo on 500, got %q", acao)
	}
	if acac := w.Header().Get("Access-Control-Allow-Credentials"); acac != "true" {
		t.Fatalf("env origin: expected ACA-Credentials=true on 500, got %q", acac)
	}
}
