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

// TestIsIngestPath pins the byte-tight boundary of the tokenless DSN-ingest
// allow-rule: POST + an ingest-root prefix + an envelope|store suffix ONLY. The
// two roots — /v1/event/ (a minted DSN) and /v1/o11y/api/ (a stock Sentry SDK's
// appended suffix) — go through one selector and must behave identically. It
// MUST NOT widen to a bare root prefix (that would expose the error-plane read
// APIs — issues/discover/projects — to tokenless callers).
func TestIsIngestPath(t *testing.T) {
	cases := []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/v1/event/019f5339-28a4-78d1/envelope/", true},
		{http.MethodPost, "/v1/event/019f5339-28a4-78d1/store/", true},
		{http.MethodPost, "/v1/event/acme/envelope", true}, // slash-less tolerated
		{http.MethodPost, "/v1/event/acme/store", true},
		{http.MethodPost, "/v1/o11y/api/acme/envelope/", true}, // the second root, same rule
		{http.MethodPost, "/v1/o11y/api/acme/store", true},
		{http.MethodGet, "/v1/event/acme/envelope/", false},           // ingest is POST-only
		{http.MethodGet, "/v1/o11y/api/acme/envelope/", false},        // POST-only, both roots
		{http.MethodPost, "/v1/event/acme/issues", false},             // a READ path — must stay gated
		{http.MethodPost, "/v1/o11y/api/acme/issues", false},          // a READ path — must stay gated
		{http.MethodPost, "/v1/event/", false},                        // bare root — not ingest
		{http.MethodPost, "/v1/event", false},                         // bare, no trailing slash
		{http.MethodPost, "/v1/o11y/api/", false},                     // bare root — not ingest
		{http.MethodPost, "/v1/eventX/acme/envelope/", false},         // prefix boundary: needs the '/'
		{http.MethodPost, "/v1/sentinel/acme/envelope/", false},       // not an ingest root
		{http.MethodPost, "/v1/event/acme/envelope/../issues", false}, // suffix anchor defeats traversal
	}
	for _, c := range cases {
		if got := isIngestPath(c.method, c.path); got != c.want {
			t.Errorf("isIngestPath(%q, %q) = %v, want %v", c.method, c.path, got, c.want)
		}
	}
}

// The security boundary end-to-end through the middleware: the ingest verbs are
// reachable WITHOUT a token (DSN-authed downstream at cloud), but a read on the
// same root still 401s without identity — the exact non-widening property RED
// requires on a public tokenless edge.
func TestAuthMiddleware_IngestBypassButReadsRequireAuth(t *testing.T) {
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

	// Tokenless ingest passes through (not 401) -> reaches DSN auth at cloud.
	// Both roots, both verbs.
	for _, path := range []string{
		"/v1/event/019f5339/envelope/",
		"/v1/event/019f5339/store/",
		"/v1/o11y/api/019f5339/envelope/",
	} {
		if code := do(http.MethodPost, path); code == http.StatusUnauthorized {
			t.Errorf("tokenless ingest %q was blocked (401); it must pass through to DSN auth", path)
		}
	}

	// A read on the SAME root is not an ingest verb and stays JWT-gated — this is
	// the property that must not widen.
	if code := do(http.MethodPost, "/v1/event/019f5339/issues"); code != http.StatusUnauthorized {
		t.Errorf("tokenless read under an ingest root returned %d, want 401 — reads must stay JWT-gated", code)
	}
	if code := do(http.MethodGet, "/v1/o11y/api/019f5339/issues"); code != http.StatusUnauthorized {
		t.Errorf("tokenless read under an ingest root returned %d, want 401 — reads must stay JWT-gated", code)
	}
	// A GET to the ingest path is not the ingest verb -> still gated.
	if code := do(http.MethodGet, "/v1/event/019f5339/envelope/"); code != http.StatusUnauthorized {
		t.Errorf("GET on the ingest path returned %d, want 401 (ingest is POST-only)", code)
	}
	// The bare root is not ingest -> gated.
	if code := do(http.MethodPost, "/v1/event/"); code != http.StatusUnauthorized {
		t.Errorf("POST to the bare /v1/event/ root returned %d, want 401 (not an ingest verb)", code)
	}
}
