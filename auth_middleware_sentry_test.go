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

// TestIsSentryIngestPath pins the byte-tight boundary of the Hanzo Sentry
// DSN-ingest allow-rule: POST + /v1/sentry/ prefix + envelope|store suffix ONLY.
// It MUST NOT widen to a bare /v1/sentry/ prefix (that would expose the Sentry
// read APIs — issues/discover/projects — to tokenless callers).
func TestIsSentryIngestPath(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/v1/sentry/019f5339-28a4-78d1/envelope/", true},
		{http.MethodPost, "/v1/sentry/019f5339-28a4-78d1/store/", true},
		{http.MethodPost, "/v1/sentry/acme/envelope", true}, // slash-less tolerated
		{http.MethodPost, "/v1/sentry/acme/store", true},
		{http.MethodGet, "/v1/sentry/acme/envelope/", false},           // ingest is POST-only
		{http.MethodPost, "/v1/sentry/issues", false},                  // a READ API — must stay gated
		{http.MethodPost, "/v1/sentry/acme/issues", false},             // a READ API — must stay gated
		{http.MethodGet, "/v1/sentry/issues", false},                   // read
		{http.MethodPost, "/v1/sentry/", false},                        // bare prefix — not ingest
		{http.MethodPost, "/v1/sentry", false},                         // bare, no trailing slash
		{http.MethodPost, "/v1/sentryX/acme/envelope/", false},         // prefix boundary: needs the '/'
		{http.MethodPost, "/v1/o11y/api/acme/envelope/", false},        // that is the sibling matcher, not this one
		{http.MethodPost, "/v1/sentry/acme/envelope/../issues", false}, // suffix anchor defeats traversal
	}
	for _, c := range cases {
		if got := isSentryIngestPath(c.method, c.path); got != c.want {
			t.Errorf("isSentryIngestPath(%q, %q) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// The security boundary end-to-end through the middleware: the Sentry ingest verbs
// are reachable WITHOUT a token (DSN-authed downstream at cloud), but every Sentry
// read still 401s without identity — the exact non-widening property RED requires
// on a public tokenless edge.
func TestAuthMiddleware_SentryIngestBypassButReadsRequireAuth(t *testing.T) {
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

	// Tokenless ingest passes through (not 401) → reaches DSN auth at cloud.
	if code := do(http.MethodPost, "/v1/sentry/019f5339/envelope/"); code == http.StatusUnauthorized {
		t.Errorf("tokenless sentry envelope ingest was blocked (401); it must pass through to DSN auth")
	}
	if code := do(http.MethodPost, "/v1/sentry/019f5339/store/"); code == http.StatusUnauthorized {
		t.Errorf("tokenless sentry store ingest was blocked (401); it must pass through to DSN auth")
	}

	// Tokenless READS are rejected — the allow-rule must NOT widen to reads.
	if code := do(http.MethodGet, "/v1/sentry/issues"); code != http.StatusUnauthorized {
		t.Errorf("tokenless sentry issues read returned %d, want 401 — reads must stay JWT-gated", code)
	}
	if code := do(http.MethodGet, "/v1/sentry/019f5339/issues"); code != http.StatusUnauthorized {
		t.Errorf("tokenless sentry project-issues read returned %d, want 401 — reads must stay JWT-gated", code)
	}
	// A GET to the ingest path is not the ingest verb → still gated.
	if code := do(http.MethodGet, "/v1/sentry/019f5339/envelope/"); code != http.StatusUnauthorized {
		t.Errorf("GET on the sentry ingest path returned %d, want 401 (ingest is POST-only)", code)
	}
	// The bare prefix is not ingest → gated.
	if code := do(http.MethodPost, "/v1/sentry/"); code != http.StatusUnauthorized {
		t.Errorf("POST to the bare /v1/sentry/ prefix returned %d, want 401 (not an ingest verb)", code)
	}
}
