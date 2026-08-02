// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// gin-driven: this suite drives the LEGACY Lura edge's transports
// (legacy_transports.go), which exist only under this tag. The policies it
// exercises are framework-free values shared with the zip edge, and
// transport_parity_test.go asserts the two edges answer alike.

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIsErrorIngestPath(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/v1/o11y/api/acme/envelope/", true},
		{http.MethodPost, "/v1/o11y/api/acme/store/", true},
		{http.MethodPost, "/v1/o11y/api/acme/envelope", true}, // slash-less tolerated
		{http.MethodPost, "/v1/o11y/api/00000000-0000/store", true},
		{http.MethodGet, "/v1/o11y/api/acme/envelope/", false},  // ingest is POST-only
		{http.MethodPost, "/v1/o11y/api/v3/query_range", false}, // a READ API — must stay gated
		{http.MethodPost, "/v1/o11y/api/", false},               // bare prefix — not ingest
		{http.MethodPost, "/v1/o11y/errortracking/issues", false},
		{http.MethodPost, "/v1/iam/api/acme/envelope/", false}, // wrong service prefix
	}
	for _, c := range cases {
		if got := isErrorIngestPath(c.method, c.path); got != c.want {
			t.Errorf("isErrorIngestPath(%q, %q) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// The security boundary: with AUTH_REQUIRE=true, the Sentry ingest verbs are
// reachable WITHOUT a token (DSN-authed downstream), but every other /v1/o11y read
// still 401s without identity — the exact property RED required.
func TestAuthMiddleware_ErrorIngestBypassButReadsRequireAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mw := NewAuthMiddleware(AuthConfig{Enabled: true, RequireAuth: true, JWKSURL: "http://127.0.0.1:0/jwks"})

	engine := gin.New()
	engine.Use(mw)
	engine.Any("/*path", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	do := func(method, path string) int {
		req := httptest.NewRequest(method, path, nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec.Code
	}

	// Tokenless ingest passes through (not 401).
	if code := do(http.MethodPost, "/v1/o11y/api/acme/envelope/"); code == http.StatusUnauthorized {
		t.Errorf("tokenless envelope ingest was blocked (401); it must pass through to DSN auth")
	}
	if code := do(http.MethodPost, "/v1/o11y/api/acme/store/"); code == http.StatusUnauthorized {
		t.Errorf("tokenless store ingest was blocked (401); it must pass through to DSN auth")
	}

	// Tokenless READ is rejected — the /v1/o11y/api/ allowlist must NOT be broad.
	if code := do(http.MethodPost, "/v1/o11y/api/v3/query_range"); code != http.StatusUnauthorized {
		t.Errorf("tokenless o11y read returned %d, want 401 — reads must stay JWT-gated", code)
	}
	if code := do(http.MethodGet, "/v1/o11y/errortracking/issues"); code != http.StatusUnauthorized {
		t.Errorf("tokenless issues read returned %d, want 401 — reads must stay JWT-gated", code)
	}
	// A GET to the ingest path is not the ingest verb → still gated.
	if code := do(http.MethodGet, "/v1/o11y/api/acme/envelope/"); code != http.StatusUnauthorized {
		t.Errorf("GET on the ingest path returned %d, want 401 (ingest is POST-only)", code)
	}
}
