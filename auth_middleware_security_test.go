// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// gin-driven: this suite drives the LEGACY Lura edge's transports
// (legacy_transports.go), which exist only under this tag. The policies it
// exercises are framework-free values shared with the zip edge, and
// transport_parity_test.go asserts the two edges answer alike.

package gateway

// Security regression tests for auth middleware.
//
// These tests exist to prevent reintroduction of auth bypass vulnerabilities.
// They cover: X-Identity header injection, JWT issuer validation, and correct
// identity header propagation on valid auth.
//
// Every test in this file must continue to pass before any merge to main.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/authz"
	"github.com/hanzoai/gateway/v2/token"
)

// setupMiddlewareWithJWKS creates a gin engine with the auth middleware
// wired to a test JWKS server. Returns the engine and test JWKS helper.
// The caller must defer jwksServer.Close().
func setupMiddlewareWithJWKS(t *testing.T, overrideCfg func(*AuthConfig)) (*gin.Engine, *testJWKS, *httptest.Server) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)

	cfg := AuthConfig{
		Enabled:        true,
		JWKSURL:        jwksServer.URL,
		Issuer:         "https://hanzo.id",
		Audiences:      []string{"https://api.hanzo.ai"},
		BillingEnabled: false, // Disable billing for security tests
		PublicPaths:    []string{"/healthz"},
		PublicHosts:    []string{"hanzo.id"},
		RequireAuth:    true,
	}
	if overrideCfg != nil {
		overrideCfg(&cfg)
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))
	return r, tj, jwksServer
}

// --- Test 1: X-Identity Header Injection Prevention on API Key Path ---

func TestAPIKeyAuth_StripsIncomingXIdentityHeaders(t *testing.T) {
	r, _, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotOrgID, gotUserID, gotEmail string
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		gotOrgID = c.Request.Header.Get("X-Org-Id")
		gotUserID = c.Request.Header.Get("X-User-Id")
		gotEmail = c.Request.Header.Get("X-User-Email")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer sk-test-key-abcdef")
	// Attacker injects forged identity headers
	req.Header.Set("X-User-Id", "attacker")
	req.Header.Set("X-Org-Id", "victim-org")
	req.Header.Set("X-User-Email", "attacker@evil.com")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for API key passthrough, got %d", w.Code)
	}
	if gotOrgID != "" {
		t.Errorf("SECURITY: X-Org-Id was NOT stripped on API key path, got %q", gotOrgID)
	}
	if gotUserID != "" {
		t.Errorf("SECURITY: X-User-Id was NOT stripped on API key path, got %q", gotUserID)
	}
	if gotEmail != "" {
		t.Errorf("SECURITY: X-User-Email was NOT stripped on API key path, got %q", gotEmail)
	}
}

// --- Test 2: JWT Empty Issuer Rejection ---

func TestJWTAuth_RejectsEmptyIssuer(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create JWT with empty issuer
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.RegisteredClaims.Issuer = "" // Empty issuer -- this MUST be rejected
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: empty issuer JWT should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("SECURITY: empty issuer JWT reached the backend handler -- auth bypass!")
	}
}

// --- Test 3: JWT Missing Issuer Rejection ---

func TestJWTAuth_RejectsMissingIssuer(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create a JWT with no issuer claim at all.
	// We build claims manually using a map to ensure "iss" is completely absent.
	now := time.Now()
	claimsMap := map[string]interface{}{
		"sub":   "alice",
		"aud":   []string{"https://api.hanzo.ai"},
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"owner": "hanzo",
		"name":  "Alice",
		"email": "alice@hanzo.ai",
		// No "iss" key at all
	}
	token := tj.signToken(t, claimsMap)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: missing issuer JWT should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("SECURITY: missing issuer JWT reached the backend handler -- auth bypass!")
	}
}

// --- Test 4: Valid JWT Still Works ---

func TestJWTAuth_AcceptsValidIssuer(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotOrgID, gotUserID, gotEmail string
	r.GET("/api/test", func(c *gin.Context) {
		gotOrgID = c.Request.Header.Get("X-Org-Id")
		gotUserID = c.Request.Header.Get("X-User-Id")
		gotEmail = c.Request.Header.Get("X-User-Email")
		c.Status(http.StatusOK)
	})

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("valid JWT should get 200, got %d", w.Code)
	}
	if gotOrgID != "hanzo" {
		t.Errorf("X-Org-Id = %q, want %q", gotOrgID, "hanzo")
	}
	if gotUserID != "alice" {
		t.Errorf("X-User-Id = %q, want %q", gotUserID, "alice")
	}
	if gotEmail != "alice@hanzo.ai" {
		t.Errorf("X-User-Email = %q, want %q", gotEmail, "alice@hanzo.ai")
	}
}

// --- Test 5: X-Identity Headers Set Correctly on Valid Auth ---

func TestValidAuth_SetsCorrectXIdentityHeaders(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotOrgID, gotUserID, gotEmail string
	r.GET("/api/test", func(c *gin.Context) {
		gotOrgID = c.Request.Header.Get("X-Org-Id")
		gotUserID = c.Request.Header.Get("X-User-Id")
		gotEmail = c.Request.Header.Get("X-User-Email")
		c.Status(http.StatusOK)
	})

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	// The MEMBERSHIP SET is the subject's org. Setting only `owner` would set the org
	// of the APP the token was minted through, which is not who bob is.
	claims.Orgs = []authz.Membership{{Org: "acme-corp", Role: authz.Member}}
	claims.RegisteredClaims.Subject = "bob"
	claims.Email = "bob@acme-corp.com"
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	// Attacker tries to override with forged headers alongside a valid JWT
	req.Header.Set("X-Org-Id", "evil-org")
	req.Header.Set("X-User-Id", "evil-admin")
	req.Header.Set("X-User-Email", "admin@evil.com")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("valid JWT should get 200, got %d", w.Code)
	}
	// Headers MUST come from the validated JWT, NOT from the forged request headers
	if gotOrgID != "acme-corp" {
		t.Errorf("SECURITY: X-Org-Id = %q, want %q (from the signed membership set)", gotOrgID, "acme-corp")
	}
	if gotUserID != "bob" {
		t.Errorf("SECURITY: X-User-Id = %q, want %q (from JWT sub claim)", gotUserID, "bob")
	}
	if gotEmail != "bob@acme-corp.com" {
		t.Errorf("SECURITY: X-User-Email = %q, want %q (from JWT email claim)", gotEmail, "bob@acme-corp.com")
	}
}

// TestValidAuth_WritesProjectFromClaim proves the org SUB-SCOPE X-Project-Id is
// written from the validated JWT `project` claim (exactly like X-Org-Id from
// `owner`) and a forged client X-Project-Id can never survive. With no project
// claim the header is omitted (default project), preserving single-project behavior.
func TestValidAuth_WritesProjectFromClaim(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotProject string
	r.GET("/api/test", func(c *gin.Context) {
		gotProject = c.Request.Header.Get("X-Project-Id")
		c.Status(http.StatusOK)
	})

	// (a) JWT carries a non-default project → written; forged header dropped.
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.Owner = "acme-corp"
	claims.Project = "research"
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims))
	req.Header.Set("X-Project-Id", "victim-project") // forgery attempt
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("valid JWT should get 200, got %d", w.Code)
	}
	if gotProject != "research" {
		t.Errorf("SECURITY: X-Project-Id = %q, want %q (from JWT project claim, not the forged header)", gotProject, "research")
	}

	// (b) No project claim → default project → header omitted.
	gotProject = "sentinel"
	claims2 := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims2.Owner = "acme-corp"
	req2 := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req2.Host = "api.hanzo.ai"
	req2.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims2))
	req2.Header.Set("X-Project-Id", "victim-project") // forgery attempt
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if gotProject != "" {
		t.Errorf("SECURITY: X-Project-Id = %q, want empty (no project claim ⟹ default, forged header dropped)", gotProject)
	}
}

// --- Test 6: No X-Identity Header Passthrough on Any Auth Path ---

func TestAllAuthPaths_NoXIdentityPassthrough(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	// Build a valid token for the JWT path test
	validToken := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai"))

	forgedHeaders := map[string]string{
		"X-Org-Id":           "forged-org",
		"X-User-Id":          "forged-admin",
		"X-User-Email":       "forged@evil.com",
		"X-User-Permissions": "20",            // Admin|Live attempted forgery
		"X-Hanzo-Custom":     "forged-custom", // Mixed case to test case-insensitive stripping
	}

	tests := []struct {
		name        string
		authHeader  string // Authorization header value
		host        string
		path        string
		requireAuth bool
		expectCode  int
	}{
		{
			name:        "API key (sk-*) with forged X-Identity headers",
			authHeader:  "Bearer sk-live-test-key-12345",
			host:        "api.hanzo.ai",
			path:        "/v1/chat/completions",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "API key (hk-*) with forged X-Identity headers",
			authHeader:  "Bearer hk-0d2eb9cfafd049389f2904cad770a9d8",
			host:        "api.hanzo.ai",
			path:        "/v1/chat/completions",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "API key (fw_*) with forged X-Identity headers",
			authHeader:  "Bearer fw_test_fireworks_key",
			host:        "api.hanzo.ai",
			path:        "/v1/chat/completions",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "Widget key (hz_*) with forged X-Identity headers",
			authHeader:  "Bearer hz_widget_public",
			host:        "api.hanzo.ai",
			path:        "/v1/chat/completions",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "Valid JWT with forged X-Identity headers",
			authHeader:  "Bearer " + validToken,
			host:        "api.hanzo.ai",
			path:        "/api/test",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "No auth (optional) with forged X-Identity headers",
			authHeader:  "",
			host:        "api.hanzo.ai",
			path:        "/api/test",
			requireAuth: false,
			expectCode:  http.StatusOK,
		},
		{
			name:        "Public path with forged X-Identity headers",
			authHeader:  "",
			host:        "api.hanzo.ai",
			path:        "/healthz",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "Public host with forged X-Identity headers",
			authHeader:  "",
			host:        "hanzo.id",
			path:        "/api/test",
			requireAuth: true,
			expectCode:  http.StatusOK,
		},
		{
			name:        "Auth disabled with forged X-Identity headers",
			authHeader:  "",
			host:        "api.hanzo.ai",
			path:        "/api/test",
			requireAuth: false,
			expectCode:  http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)

			// Special case: "auth disabled" test
			enabled := true
			if tt.name == "Auth disabled with forged X-Identity headers" {
				enabled = false
			}

			cfg := AuthConfig{
				Enabled:        enabled,
				JWKSURL:        jwksServer.URL,
				Issuer:         "https://hanzo.id",
				Audiences:      []string{"https://api.hanzo.ai"},
				BillingEnabled: false,
				PublicPaths:    []string{"/healthz"},
				PublicHosts:    []string{"hanzo.id"},
				RequireAuth:    tt.requireAuth,
			}

			r := gin.New()
			r.Use(NewAuthMiddleware(cfg))

			var receivedHeaders map[string]string
			handler := func(c *gin.Context) {
				receivedHeaders = make(map[string]string)
				for key := range forgedHeaders {
					receivedHeaders[key] = c.Request.Header.Get(key)
				}
				c.Status(http.StatusOK)
			}

			r.GET(tt.path, handler)
			r.POST(tt.path, handler)

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.path == "/v1/chat/completions" {
				req = httptest.NewRequest(http.MethodPost, tt.path, nil)
			}
			req.Host = tt.host
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			// Inject all forged headers
			for k, v := range forgedHeaders {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectCode {
				t.Fatalf("expected status %d, got %d", tt.expectCode, w.Code)
			}

			// If the handler was reached, verify no forged X-Identity headers survived
			if receivedHeaders != nil {
				for key, forgedVal := range forgedHeaders {
					got := receivedHeaders[key]
					// For the valid JWT path, X-Identity headers are SET from the JWT
					// claims. They must NOT match the forged values.
					if got == forgedVal {
						t.Errorf("SECURITY: forged header %s=%q was NOT stripped", key, forgedVal)
					}
				}
			}
		})
	}
}

// --- Test 7: API Key Auth Doesn't Skip Validation ---

func TestAPIKeyAuth_ValidatesKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// A request with a token that is NOT a recognized API key prefix and
	// NOT a valid JWT should be rejected when auth is required.
	r, _, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	invalidTokens := []struct {
		name  string
		token string
	}{
		{"random string", "not-a-valid-token"},
		{"almost an API key", "sk"},
		{"empty bearer", ""},
		{"jwt-like but invalid", "eyJhbGciOiJSUzI1NiJ9.invalid.signature"},
		{"api key prefix but mangled JWT attempt", "xx-fake-key"},
	}

	for _, tt := range invalidTokens {
		t.Run(tt.name, func(t *testing.T) {
			backendReached = false
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			req.Host = "api.hanzo.ai"
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			r.ServeHTTP(w, req)

			if tt.token == "" {
				// No token at all with RequireAuth=true -> 401
				if w.Code != http.StatusUnauthorized {
					t.Errorf("empty token should get 401, got %d", w.Code)
				}
			} else {
				// Invalid token (not API key, not valid JWT) -> 401
				if w.Code != http.StatusUnauthorized {
					t.Errorf("invalid token %q should get 401, got %d", tt.token, w.Code)
				}
			}

			if backendReached {
				t.Errorf("SECURITY: invalid token %q reached backend", tt.token)
			}
		})
	}
}

// --- Test 8: JWT Wrong Issuer Rejection ---

func TestJWTAuth_RejectsWrongIssuer(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create JWT with wrong issuer
	claims := validClaims("https://evil-issuer.com", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: wrong issuer JWT should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("SECURITY: wrong issuer JWT reached the backend handler")
	}
}

// --- Test 9: JWT Expired Token Rejection ---

func TestJWTAuth_RejectsExpiredToken(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create expired JWT (expired 10 minutes ago, beyond the 2min leeway)
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-10 * time.Minute))
	claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-20 * time.Minute))
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expired JWT should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("expired JWT reached the backend handler")
	}
}

// --- Test 10: JWT Wrong Audience Rejection ---

func TestJWTAuth_RejectsWrongAudience(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create JWT with wrong audience
	claims := validClaims("https://hanzo.id", "https://wrong-audience.com")
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong audience JWT should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("wrong audience JWT reached the backend handler")
	}
}

// --- Test 11: JWT Signed With Wrong Key Rejection ---

func TestJWTAuth_RejectsWrongSigningKey(t *testing.T) {
	// Set up middleware with one key, sign token with a different key
	r, _, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	// Create a DIFFERENT key to sign the token
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	raw := signAs(t, attackerKey, "attacker-key", claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+raw)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("SECURITY: JWT signed with wrong key should get 401, got %d", w.Code)
	}
	if backendReached {
		t.Error("SECURITY: JWT signed with wrong key reached the backend handler")
	}
}

// --- Test 12: stripIdentityHeaders is case-insensitive ---

func TestStripIdentityHeaders_CaseInsensitive(t *testing.T) {
	// HTTP headers are case-insensitive per RFC 7230. An attacker might try
	// alternate casings like "x-org-id" or "X-Org-Id" to bypass
	// stripping logic.
	casings := []string{
		"X-Org-Id",
		"x-org-id",
		"X-Org-Id",
		"x-ORG-ID",
		"x-user-id",
		"X-USER-EMAIL",
		"x-hanzo-custom-header",
	}

	for _, header := range casings {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(header, "forged-value")

			stripClaimed(httpHeaders{req.Header})

			if v := req.Header.Get(header); v != "" {
				t.Errorf("SECURITY: header %q was NOT stripped (got %q)", header, v)
			}
		})
	}
}

// --- Test 13: Non-X-Identity headers are preserved ---

func TestStripIdentityHeaders_PreservesOtherHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer some-token")
	req.Header.Set("X-Request-Id", "req-123")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	// This one should be stripped
	req.Header.Set("X-Org-Id", "forged")

	stripClaimed(httpHeaders{req.Header})

	preserved := map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer some-token",
		"X-Request-Id":    "req-123",
		"X-Forwarded-For": "1.2.3.4",
	}
	for k, want := range preserved {
		if got := req.Header.Get(k); got != want {
			t.Errorf("header %s was modified: got %q, want %q", k, got, want)
		}
	}
	if v := req.Header.Get("X-Org-Id"); v != "" {
		t.Errorf("X-Org-Id should have been stripped, got %q", v)
	}
}

// --- Test 14: Comprehensive forged header name variants ---

func TestStripIdentityHeaders_AllVariants(t *testing.T) {
	// The canonical 3 identity headers are X-User-Id, X-Org-Id, X-Roles.
	// Gateway-emitted auxiliaries: X-User-Email, X-Phone-Number, X-User-IsAdmin.
	// Every other identity-like header (legacy + vendor-prefixed) MUST be stripped.
	attackerHeaders := []string{
		// Canonical identity headers — attacker may not forge these
		"X-User-Id",
		"X-Org-Id",
		"X-Roles",
		"X-User-Permissions",
		// Gateway-emitted auxiliaries
		"X-User-Email",
		"X-Phone-Number",
		"X-User-IsAdmin",
		"X-User-IsGlobalAdmin", // PLATFORM superadmin (money authority) — MUST be stripped
		// Legacy non-canonical identity headers
		"X-User-Role",  // singular
		"X-User-Roles", // plural (renamed to X-Roles)
		"X-User-Name",
		"X-Tenant-Id",
		"X-Tenant-ID",
		"X-Org",
		// Org sub-scope selector: a raw client copy is forgeable and MUST be
		// stripped on ingress; the trusted value is rewritten from the validated
		// JWT `project` claim (InjectIdentity / auth_middleware), never trusted raw.
		"X-Project-Id",
		// Vendor-prefixed legacy headers
		"X-Hanzo-Role",
		"X-Hanzo-Scope",
		"X-Hanzo-Admin",
		"X-Hanzo-Whatever-New-Header",
		"X-IAM-User-Id",
		"X-IAM-Org-Id",
		"X-IAM-Roles",
		"X-IAM-User-Email",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, h := range attackerHeaders {
		req.Header.Set(h, "forged")
	}

	stripClaimed(httpHeaders{req.Header})

	for _, h := range attackerHeaders {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("SECURITY: header %q was NOT stripped", h)
		}
	}
}

// --- Test 14: the identity headers a validated token earns, and the two it does not ---

// headersFor runs one request through the live middleware and reports the identity
// the backend would see.
func headersFor(t *testing.T, tj *testJWKS, jwksURL string, claims map[string]any) map[string]string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	seen := map[string]string{}
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled: true, JWKSURL: jwksURL, Issuer: "https://hanzo.id",
		Audiences: []string{"https://api.hanzo.ai"}, RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		for _, h := range append(append([]string{}, authz.Headers...), authz.Retired...) {
			seen[h] = c.Request.Header.Get(h)
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("request was refused with %d: %s", w.Code, w.Body.String())
	}
	return seen
}

// An ORG ADMIN gets the org-admin header and NOT the platform one. isAdmin is IAM's
// org-role bit; writing platform authority from it made every org owner a platform
// admin, which is the escalation this whole path was rebuilt to make unrepeatable.
func TestOrgAdminGetsNoPlatformAuthority(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	got := headersFor(t, tj, jwksServer.URL, iamToken("hanzo", map[string]any{
		"isAdmin": true,
		"orgs":    []map[string]any{{"org": "hanzo", "role": "admin"}},
	}))

	if got[authz.HeaderUserAdmin] != "" {
		t.Errorf("%s = %q — an org admin was given PLATFORM authority",
			authz.HeaderUserAdmin, got[authz.HeaderUserAdmin])
	}
	if got[authz.HeaderUserOrgAdmin] != "true" {
		t.Errorf("%s = %q, want true", authz.HeaderUserOrgAdmin, got[authz.HeaderUserOrgAdmin])
	}
	if got[authz.HeaderOrg] != "hanzo" {
		t.Errorf("%s = %q, want hanzo", authz.HeaderOrg, got[authz.HeaderOrg])
	}
	if got[authz.HeaderUser] != "uuid-alice" {
		t.Errorf("%s = %q, want uuid-alice", authz.HeaderUser, got[authz.HeaderUser])
	}
	if got[authz.HeaderUserEmail] != "alice@hanzo.ai" {
		t.Errorf("%s = %q, want alice@hanzo.ai", authz.HeaderUserEmail, got[authz.HeaderUserEmail])
	}

	// The money bit-field carries `live` (a real top-up, on the org role) and NOT
	// `admin` (platform money authority). Commerce reads this with intersection
	// semantics, so an org owner holding admin was the free-money hole.
	bits := got[authz.HeaderUserPermissions]
	if bits == "" {
		t.Fatalf("%s was not written for an org admin", authz.HeaderUserPermissions)
	}
	n, err := strconv.ParseInt(bits, 10, 64)
	if err != nil {
		t.Fatalf("%s = %q, not a bit-field", authz.HeaderUserPermissions, bits)
	}
	if n&permissionBits["admin"] != 0 {
		t.Errorf("an org admin carries the PLATFORM money bit (%s=%q)", authz.HeaderUserPermissions, bits)
	}
	if n&permissionBits["live"] == 0 {
		t.Errorf("an org admin lost the live bit (%s=%q) — their own real top-up would break", authz.HeaderUserPermissions, bits)
	}
}

// A platform operator gets both the platform header and the money bit.
func TestPlatformOperatorGetsPlatformAuthority(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	got := headersFor(t, tj, jwksServer.URL, iamToken(authz.AdminOrg, map[string]any{
		"isAdmin": true,
		"orgs":    []map[string]any{{"org": authz.AdminOrg, "role": "admin"}},
	}))

	if got[authz.HeaderUserAdmin] != "true" {
		t.Errorf("%s = %q, want true", authz.HeaderUserAdmin, got[authz.HeaderUserAdmin])
	}
	n, _ := strconv.ParseInt(got[authz.HeaderUserPermissions], 10, 64)
	if n&permissionBits["admin"] == 0 {
		t.Errorf("the platform operator lost the money bit (%s=%q)",
			authz.HeaderUserPermissions, got[authz.HeaderUserPermissions])
	}
}

// A MACHINE in the reserved admin org gets neither, and cannot name another tenant.
// IAM's client_credentials grant signs no membership set, which is what marks it a
// machine; the predicate that used to look for tokenType "application" never fired,
// because IAM assigns that value nowhere.
func TestAdminOrgMachineGetsNoAuthority(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	claims := iamToken(authz.AdminOrg, map[string]any{"isAdmin": true, "tokenType": "access-token"})
	claims["sub"] = authz.AdminOrg + "/kms-sync"
	delete(claims, "orgs")

	gin.SetMode(gin.TestMode)
	seen := map[string]string{}
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled: true, JWKSURL: jwksServer.URL, Issuer: "https://hanzo.id",
		Audiences: []string{"https://api.hanzo.ai"}, RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		for _, h := range authz.Headers {
			seen[h] = c.Request.Header.Get(h)
		}
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims))
	req.Header.Set(authz.HeaderOrg, "victim") // the org it asks to act in
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if seen[authz.HeaderUserAdmin] != "" {
		t.Errorf("an admin-org machine was given %s=%q", authz.HeaderUserAdmin, seen[authz.HeaderUserAdmin])
	}
	if seen[authz.HeaderUserOrgAdmin] != "" {
		t.Errorf("an admin-org machine was given %s=%q", authz.HeaderUserOrgAdmin, seen[authz.HeaderUserOrgAdmin])
	}
	// NO org: a machine's org lives only in the `owner` claim, which cannot be told
	// apart from the app a human signed in through.
	if seen[authz.HeaderOrg] != "" {
		t.Errorf("an admin-org machine was given org %q, want none", seen[authz.HeaderOrg])
	}
	if n, _ := strconv.ParseInt(seen[authz.HeaderUserPermissions], 10, 64); n&permissionBits["admin"] != 0 {
		t.Errorf("an admin-org machine carries the money bit (%q)", seen[authz.HeaderUserPermissions])
	}
}

// X-Roles and X-Phone-Number are RETIRED: no edge writes them, and a token carrying
// the claims the old parsers read changes nothing. IAM emits neither `roles` nor
// `phone` — they are absent from the signed claim set and from claims_supported —
// so the three-shape parsers were reading a claim that never arrived.
func TestRetiredHeadersAreNeverWritten(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	got := headersFor(t, tj, jwksServer.URL, iamToken("hanzo", map[string]any{
		"orgs":  []map[string]any{{"org": "hanzo", "role": "member"}},
		"roles": []map[string]string{{"name": "admin"}, {"name": "operator"}},
		"phone": "+15555550100",
	}))

	for _, h := range authz.Retired {
		if got[h] != "" {
			t.Errorf("retired header %s was written as %q", h, got[h])
		}
	}
}

// --- Test 15: validateToken rejects multiple issuer attack vectors ---

func TestValidateToken_IssuerAttackVectors(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	validator := token.NewValidator(token.Config{
		JWKSURL: jwksServer.URL, Issuers: []string{"https://hanzo.id"},
		Audiences: []string{"https://api.hanzo.ai"},
	})

	tests := []struct {
		name   string
		issuer string
	}{
		{"empty issuer", ""},
		{"whitespace issuer", " "},
		{"wrong issuer", "https://evil.com"},
		{"partial match issuer", "https://hanzo.id.evil.com"},
		{"issuer with trailing slash", "https://hanzo.id/"},
		{"issuer subdomain", "https://sub.hanzo.id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			claims := map[string]interface{}{
				"sub":   "alice",
				"aud":   []string{"https://api.hanzo.ai"},
				"iat":   now.Add(-1 * time.Minute).Unix(),
				"exp":   now.Add(10 * time.Minute).Unix(),
				"owner": "hanzo",
				"email": "alice@hanzo.ai",
			}
			if tt.issuer != "" {
				claims["iss"] = tt.issuer
			}
			// No "iss" at all for empty issuer test

			raw := tj.signToken(t, claims)
			_, err := validator.VerifyRaw(raw)
			if err == nil {
				t.Errorf("SECURITY: the edge accepted issuer %q -- should have been rejected", tt.issuer)
			}
		})
	}
}

// --- Test 16: Billing returns 402 when balance is zero ---

func TestBillingCheck_Returns402WhenNoBalance(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	// Mock billing server that returns zero balance
	billingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(billingResponse{
			User:      "hanzo/alice",
			Currency:  "usd",
			Balance:   0,
			Holds:     0,
			Available: 0,
		})
	}))
	defer billingServer.Close()

	cfg := AuthConfig{
		Enabled:        true,
		JWKSURL:        jwksServer.URL,
		Issuer:         "https://hanzo.id",
		Audiences:      []string{"https://api.hanzo.ai"},
		BillingURL:     billingServer.URL,
		BillingToken:   "test-token",
		BillingEnabled: true,
		PublicPaths:    []string{},
		PublicHosts:    []string{},
		RequireAuth:    true,
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))

	backendReached := false
	r.GET("/api/test", func(c *gin.Context) {
		backendReached = true
		c.Status(http.StatusOK)
	})

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Errorf("zero balance should get 402, got %d", w.Code)
	}
	if backendReached {
		t.Error("request with zero balance should not reach backend")
	}
}

// --- Test 16a: billing is PATH-SCOPED to the must-gate surface ---
// With BillingPaths set, a zero-balance org is 402'd on a must-gate route
// but NOT balance-gated on an off-scope route (the AI/validated surface,
// which bills per-token downstream). This is the guarantee that turning
// edge billing ON for the must-gate routes never breaks the 171.
func TestBillingCheck_PathScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	// Commerce mock: every org has zero available balance.
	billingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(billingResponse{Currency: "usd", Available: 0})
	}))
	defer billingServer.Close()

	cfg := AuthConfig{
		Enabled:        true,
		JWKSURL:        jwksServer.URL,
		Issuer:         "https://hanzo.id",
		Audiences:      []string{"https://api.hanzo.ai"},
		BillingURL:     billingServer.URL,
		BillingToken:   "test-token",
		BillingEnabled: true,
		BillingPaths:   []string{"/v1/mpc/", "/v1/cloud/"}, // must-gate scope
		PublicPaths:    []string{},
		PublicHosts:    []string{},
		RequireAuth:    true,
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))
	embeddingsReached := false
	mpcReached := false
	r.POST("/v1/embeddings", func(c *gin.Context) { embeddingsReached = true; c.Status(http.StatusOK) })
	r.POST("/v1/mpc/sign", func(c *gin.Context) { mpcReached = true; c.Status(http.StatusOK) })

	token := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai"))
	do := func(path string) int {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Off-scope (AI/validated) route: zero balance MUST NOT gate it.
	if code := do("/v1/embeddings"); code != http.StatusOK {
		t.Errorf("off-scope route must not be balance-gated; got %d, want 200", code)
	}
	if !embeddingsReached {
		t.Error("off-scope route should reach backend despite zero balance")
	}

	// In-scope (must-gate) route: zero balance MUST 402.
	if code := do("/v1/mpc/sign"); code != http.StatusPaymentRequired {
		t.Errorf("must-gate route with zero balance must be 402; got %d", code)
	}
	if mpcReached {
		t.Error("must-gate route with zero balance must not reach backend")
	}
}

// --- Test 16b: gateway calls the CORRECT commerce path (/v1/billing/balance) ---
// Pins the path. If anyone reverts to /api/v1/... the mock 404s, checkBalance
// fails-closed, and this test goes 503 instead of 200 — i.e. it would have
// caught the -X theirs merge-train regression of PR #24.
func TestBillingCheck_HitsV1PathAndAllows(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	var gotPath string
	billingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != "/v1/billing/balance" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(billingResponse{
			User: "hanzo/alice", Currency: "usd",
			Balance: 5000, Holds: 0, Available: 5000,
		})
	}))
	defer billingServer.Close()

	cfg := AuthConfig{
		Enabled: true, JWKSURL: jwksServer.URL,
		Issuer: "https://hanzo.id", Audiences: []string{"https://api.hanzo.ai"},
		BillingURL: billingServer.URL, BillingToken: "test-token", BillingEnabled: true,
		PublicPaths: []string{}, PublicHosts: []string{}, RequireAuth: true,
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))
	backendReached := false
	r.GET("/api/test", func(c *gin.Context) { backendReached = true; c.Status(http.StatusOK) })

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if gotPath != "/v1/billing/balance" {
		t.Errorf("gateway must call /v1/billing/balance, called %q", gotPath)
	}
	if w.Code != http.StatusOK || !backendReached {
		t.Errorf("positive balance should reach backend with 200, got %d (reached=%v)", w.Code, backendReached)
	}
}

// --- Test 16c: gateway fails CLOSED when commerce errors (no free) ---
func TestBillingCheck_FailsClosedOnCommerceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	billingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer billingServer.Close()

	cfg := AuthConfig{
		Enabled: true, JWKSURL: jwksServer.URL,
		Issuer: "https://hanzo.id", Audiences: []string{"https://api.hanzo.ai"},
		BillingURL: billingServer.URL, BillingToken: "test-token", BillingEnabled: true,
		PublicPaths: []string{}, PublicHosts: []string{}, RequireAuth: true,
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(cfg))
	backendReached := false
	r.GET("/api/test", func(c *gin.Context) { backendReached = true; c.Status(http.StatusOK) })

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if backendReached {
		t.Error("commerce error must NOT reach backend (fail-closed, no free)")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("commerce error should yield 503 billing_unavailable, got %d", w.Code)
	}
}

// --- Test 17: Multiple X-Identity header values (multi-value attack) ---

func TestStripIdentityHeaders_MultiValueAttack(t *testing.T) {
	// HTTP allows multiple values for the same header. An attacker might
	// add multiple X-Org-Id values hoping one survives stripping.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("X-Org-Id", "forged-1")
	req.Header.Add("X-Org-Id", "forged-2")
	req.Header.Add("X-User-Id", "admin")
	req.Header.Add("X-User-Id", "root")

	stripClaimed(httpHeaders{req.Header})

	if vals := req.Header.Values("X-Org-Id"); len(vals) != 0 {
		t.Errorf("SECURITY: X-Org-Id had %d values after stripping: %v", len(vals), vals)
	}
	if vals := req.Header.Values("X-User-Id"); len(vals) != 0 {
		t.Errorf("SECURITY: X-User-Id had %d values after stripping: %v", len(vals), vals)
	}
}

// --- Test 18: Cookie-based token with forged headers ---

func TestCookieAuth_StripsForgedXIdentityHeaders(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotOrgID, gotUserID string
	r.GET("/api/test", func(c *gin.Context) {
		gotOrgID = c.Request.Header.Get("X-Org-Id")
		gotUserID = c.Request.Header.Get("X-User-Id")
		c.Status(http.StatusOK)
	})

	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.Orgs = []authz.Membership{{Org: "legit-org", Role: authz.Member}}
	claims.RegisteredClaims.Subject = "legit-user"
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	// Token via cookie instead of Authorization header
	req.AddCookie(&http.Cookie{Name: "iam_access_token", Value: token})
	// Attacker injects forged headers
	req.Header.Set("X-Org-Id", "forged-org")
	req.Header.Set("X-User-Id", "forged-user")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("cookie auth should get 200, got %d", w.Code)
	}
	// Must reflect JWT claims, not forged headers
	if gotOrgID != "legit-org" {
		t.Errorf("SECURITY: X-Org-Id = %q, want %q", gotOrgID, "legit-org")
	}
	if gotUserID != "legit-user" {
		t.Errorf("SECURITY: X-User-Id = %q, want %q", gotUserID, "legit-user")
	}
}

// --- Test 19: Publishable key (pk-*) with forged headers ---

func TestPublishableKeyAuth_StripsForgedXIdentityHeaders(t *testing.T) {
	r, _, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotOrgID string
	r.GET("/api/test", func(c *gin.Context) {
		gotOrgID = c.Request.Header.Get("X-Org-Id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer pk-publishable-key-xyz")
	req.Header.Set("X-Org-Id", "forged-org")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("pk- key should pass through, got %d", w.Code)
	}
	if gotOrgID != "" {
		t.Errorf("SECURITY: X-Org-Id was NOT stripped on pk- key path, got %q", gotOrgID)
	}
}

// --- Test 20: Concurrent header injection attempts ---

func TestConcurrentHeaderInjection(t *testing.T) {
	r, _, jwksServer := setupMiddlewareWithJWKS(t, func(cfg *AuthConfig) {
		cfg.RequireAuth = false
	})
	defer jwksServer.Close()

	var mu sync.Mutex
	type result struct {
		orgID  string
		userID string
	}
	results := make([]result, 100)

	r.GET("/api/test", func(c *gin.Context) {
		// Capture what the backend sees
		res := result{
			orgID:  c.Request.Header.Get("X-Org-Id"),
			userID: c.Request.Header.Get("X-User-Id"),
		}
		mu.Lock()
		results = append(results, res)
		mu.Unlock()
		c.Status(http.StatusOK)
	})

	// Fire 100 concurrent requests with forged headers
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
			req.Host = "api.hanzo.ai"
			req.Header.Set("X-Org-Id", fmt.Sprintf("forged-org-%d", n))
			req.Header.Set("X-User-Id", fmt.Sprintf("forged-user-%d", n))

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", n, w.Code)
			}
		}(i)
	}
	wg.Wait()

	// Verify no forged headers made it through
	mu.Lock()
	defer mu.Unlock()
	for i, res := range results {
		if res.orgID != "" {
			t.Errorf("SECURITY: request %d: forged X-Org-Id leaked: %q", i, res.orgID)
		}
		if res.userID != "" {
			t.Errorf("SECURITY: request %d: forged X-User-Id leaked: %q", i, res.userID)
		}
	}
}

// --- Test 21: X-User-Permissions forged value is stripped (Red P0-1) ---
//
// Regression for Red P0-1 (2026-04-27): commerce trusts X-User-Permissions
// as a base-10 bit.Field. Before this fix, gateway neither stripped a
// client-supplied X-User-Permissions nor wrote one from JWT. An attacker
// could send `X-User-Permissions: 16` (Admin bit) with any valid token
// and gain admin in commerce.
func TestPermissions_ForgedHeaderStripped(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotPerms string
	r.GET("/api/test", func(c *gin.Context) {
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		c.Status(http.StatusOK)
	})

	// JWT has no permissions claim and isAdmin=false → no permissions
	// should be written. The forged header MUST NOT survive.
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	// Attacker forges Admin|Live (16|4 = 20)
	req.Header.Set("X-User-Permissions", "20")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if gotPerms != "" {
		t.Errorf("SECURITY: X-User-Permissions = %q, want empty (forged value must be stripped, JWT had no perms)", gotPerms)
	}
}

// --- Test 21b: org-level admin is NOT granted the Admin money bit ---
//
// The free-money regression. An org OWNER (owner="hanzo", isAdmin=true) is an
// ORG-level admin, not a platform admin. Commerce gates every credit-creating
// and card-charging billing endpoint on TokenRequired(permission.Admin); before
// the fix the gateway wrote Admin|Live (20) for any isAdmin JWT, so an org owner
// satisfied those gates and minted unlimited free balance (live-proven as
// Dave/maxpower). The gateway must now write ONLY Live (4) for an org-level admin.
func TestPermissions_OrgAdminGetsNoAdminBit(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotPerms, gotGlobalAdmin string
	r.GET("/api/test", func(c *gin.Context) {
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		gotGlobalAdmin = c.Request.Header.Get("X-User-IsGlobalAdmin")
		c.Status(http.StatusOK)
	})

	// Org owner: isAdmin=true, owner="hanzo" (NOT the admin org), no explicit
	// permissions claim → the ONLY bits are the isAdmin-derived ones.
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.IsAdmin = true
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	// Attacker also forges the platform-superadmin header — MUST be stripped.
	req.Header.Set("X-User-IsGlobalAdmin", "true")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	// Live (4) only — NOT Admin|Live (20).
	if gotPerms != "4" {
		t.Errorf("SECURITY: org-admin X-User-Permissions = %q, want %q (Live only, no Admin money bit)", gotPerms, "4")
	}
	// The forged platform-superadmin header must not survive; an org admin is
	// not a global admin, so the gateway must not write it either.
	if gotGlobalAdmin != "" {
		t.Errorf("SECURITY: X-User-IsGlobalAdmin = %q, want empty (org admin is not global; forged value must be stripped)", gotGlobalAdmin)
	}
}

// --- Test 21c: a real global admin DOES get Admin|Live + the superadmin header ---
func TestPermissions_PlatformSudoGetsAdminBitNoHeader(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotPerms, gotGlobalAdmin string
	r.GET("/api/test", func(c *gin.Context) {
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		gotGlobalAdmin = c.Request.Header.Get("X-User-IsGlobalAdmin")
		c.Status(http.StatusOK)
	})

	// Platform sudo: owner=="admin" → full Admin|Live bits, but NO boolean header.
	claims := validClaims("https://hanzo.id", "https://api.hanzo.ai")
	claims.Owner = "admin"
	claims.IsAdmin = true
	// A user token always carries its home org first (store.MemberOrgRefs). Without
	// it this reads as a MACHINE, which holds no platform authority — so the fixture
	// has to be the shape IAM actually signs.
	claims.Orgs = []authz.Membership{{Org: "admin", Role: "admin"}}
	token := tj.signToken(t, claims)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if gotPerms != "20" {
		t.Errorf("platform-sudo X-User-Permissions = %q, want %q (Admin|Live)", gotPerms, "20")
	}
	// Platform sudo grants the Admin bit (owner=="admin") but writes NO boolean header.
	if gotGlobalAdmin != "" {
		t.Errorf("SECURITY: X-User-IsGlobalAdmin = %q, want empty — the platform-admin boolean is never written (sudo = org==admin)", gotGlobalAdmin)
	}
}

// --- Test 22: the money bit-field comes from the PREDICATES, never from a claim ---

// Three tests used to live here, one per shape of a `permissions` claim: a numeric
// bit-field, a []string of names, and IAM's []*Permission objects. IAM emits NO such
// claim — it is absent from the signed claim set (internal/oidc/jwt.go) and from
// claims_supported — so all three exercised a parser nothing ever fed, and a token
// that DID carry the claim was granted whatever bits it named.
//
// This is the invariant that replaces them, and it is stronger: the money authority
// is a function of the two predicates, and a token asserting its own permissions
// gains nothing from doing so.
func TestPermissions_ClaimCannotGrantBits(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	now := time.Now()
	claims := map[string]any{
		"iss": "https://hanzo.id", "sub": "uuid-mallory",
		"aud": []string{"https://api.hanzo.ai"},
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"owner": "acme", "preferred_username": "mallory",
		"orgs": []map[string]any{{"org": "acme", "role": "member"}},
		// Every shape the old parsers accepted, all naming the money bit.
		"permissions": []map[string]string{{"name": "admin"}},
	}

	gin.SetMode(gin.TestMode)
	var gotPerms, gotAdmin string
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled: true, JWKSURL: jwksServer.URL, Issuer: "https://hanzo.id",
		Audiences: []string{"https://api.hanzo.ai"}, RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		gotPerms = c.Request.Header.Get(authz.HeaderUserPermissions)
		gotAdmin = c.Request.Header.Get(authz.HeaderUserAdmin)
		c.Status(http.StatusOK)
	})

	for _, shape := range []any{
		[]map[string]string{{"name": "admin"}},
		[]string{"admin", "live"},
		permissionBits["admin"],
	} {
		claims["permissions"] = shape
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tj.signToken(t, claims))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
		}
		if gotPerms != "" {
			t.Errorf("SECURITY: a `permissions` claim of %T wrote %s=%q — a plain member named its own money authority",
				shape, authz.HeaderUserPermissions, gotPerms)
		}
		if gotAdmin != "" {
			t.Errorf("SECURITY: a plain member was given %s=%q", authz.HeaderUserAdmin, gotAdmin)
		}
	}
}

// --- Test 25: a GLOBAL admin's isAdmin auto-writes Admin|Live ---
//
// The Admin (money) bit is written from isAdmin ONLY for a platform (global)
// admin — here owner=="admin". An org-level admin gets Live only; that half of
// the contract is TestPermissions_OrgAdminGetsNoAdminBit (the free-money
// regression). Global-admin tooling keeps its Admin|Live so it still works.
func TestPermissions_IsAdminWritesAdminLive(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	now := time.Now()
	// No "permissions" claim, isAdmin=true, owner=="admin" (global admin org)
	// → gateway writes Admin|Live.
	claims := map[string]interface{}{
		"iss":     "https://hanzo.id",
		"sub":     "z",
		"aud":     []string{"https://api.hanzo.ai"},
		"iat":     now.Add(-1 * time.Minute).Unix(),
		"exp":     now.Add(10 * time.Minute).Unix(),
		"owner":   "admin",
		"isAdmin": true,
		"orgs":    []map[string]any{{"org": "admin", "role": "admin"}},
	}
	token := tj.signToken(t, claims)

	gin.SetMode(gin.TestMode)
	var gotIsAdmin, gotPerms string
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled:     true,
		JWKSURL:     jwksServer.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		gotIsAdmin = c.Request.Header.Get("X-User-IsAdmin")
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotIsAdmin != "true" {
		t.Errorf("X-User-IsAdmin = %q, want %q", gotIsAdmin, "true")
	}
	// Admin (16) | Live (4) = 20
	if gotPerms != "20" {
		t.Errorf("X-User-Permissions = %q, want %q (Admin|Live)", gotPerms, "20")
	}
}

// --- Test 26: No permissions claim + non-admin → no header ---

func TestPermissions_AbsentWhenNoneGranted(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	now := time.Now()
	claims := map[string]interface{}{
		"iss":   "https://hanzo.id",
		"sub":   "viewer",
		"aud":   []string{"https://api.hanzo.ai"},
		"iat":   now.Add(-1 * time.Minute).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"owner": "acme",
		// no permissions, no isAdmin
	}
	token := tj.signToken(t, claims)

	gin.SetMode(gin.TestMode)
	var sawHeader bool
	var gotPerms string
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled:     true,
		JWKSURL:     jwksServer.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		_, sawHeader = c.Request.Header[http.CanonicalHeaderKey("X-User-Permissions")]
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Documented contract: header is absent (not "0") so commerce's
	// parsePermissionsHeader returns bit.Field(0) — fail-closed.
	if sawHeader {
		t.Errorf("X-User-Permissions should be ABSENT for no-perms JWT, got %q", gotPerms)
	}
}

// --- Test 27: Unknown permission name doesn't grant any bits ---

func TestPermissions_UnknownNameIgnored(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	now := time.Now()
	claims := map[string]interface{}{
		"iss":         "https://hanzo.id",
		"sub":         "viewer",
		"aud":         []string{"https://api.hanzo.ai"},
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(10 * time.Minute).Unix(),
		"owner":       "acme",
		"permissions": []string{"made-up-policy", "another-fake-one"},
	}
	token := tj.signToken(t, claims)

	gin.SetMode(gin.TestMode)
	var gotPerms string
	var sawHeader bool
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled:     true,
		JWKSURL:     jwksServer.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		_, sawHeader = c.Request.Header[http.CanonicalHeaderKey("X-User-Permissions")]
		gotPerms = c.Request.Header.Get("X-User-Permissions")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// All names unknown -> zero bits -> header omitted.
	if sawHeader {
		t.Errorf("X-User-Permissions = %q, want ABSENT (all names unknown)", gotPerms)
	}
}

// --- Test 28: stripIdentityHeaders covers X-User-Permissions ---
//
// Direct unit test on stripIdentityHeaders so a regression in the strip
// list shows up before any middleware-level test gets a chance to mask
// it by overwriting.
func TestStripIdentityHeaders_StripsPermissions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Permissions", "20")

	stripClaimed(httpHeaders{req.Header})

	if v := req.Header.Get("X-User-Permissions"); v != "" {
		t.Errorf("SECURITY: X-User-Permissions was NOT stripped (got %q)", v)
	}
}

// --- Test 29: strip-list ⊇ write-list contract test ---
//
// Red called this out as a gap (P0-1 audit): every header the gateway
// writes downstream MUST also appear in the strip list. Otherwise a new
// write target added without a strip pair is forgeable. This test is the
// canonical link between the two lists.
func TestStripList_CoversAllWrittenHeaders(t *testing.T) {
	for _, h := range authz.Headers {
		t.Run(h, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(h, "forged-"+h)

			stripClaimed(httpHeaders{req.Header})

			if v := req.Header.Get(h); v != "" {
				t.Errorf("SECURITY: gateway writes %q but strip list does NOT cover it (got %q)", h, v)
			}
		})
	}
}

// --- Test 30: Unparseable permissions claim fails closed ---

func TestPermissions_UnparseableClaimFailsClosed(t *testing.T) {
	tj := newTestJWKS(t)
	jwksServer := tj.serveJWKS(t)
	defer jwksServer.Close()

	now := time.Now()
	claims := map[string]interface{}{
		"iss":         "https://hanzo.id",
		"sub":         "weird",
		"aud":         []string{"https://api.hanzo.ai"},
		"iat":         now.Add(-1 * time.Minute).Unix(),
		"exp":         now.Add(10 * time.Minute).Unix(),
		"owner":       "acme",
		"permissions": "not-a-list", // wrong shape entirely
	}
	token := tj.signToken(t, claims)

	gin.SetMode(gin.TestMode)
	var sawHeader bool
	r := gin.New()
	r.Use(NewAuthMiddleware(AuthConfig{
		Enabled:     true,
		JWKSURL:     jwksServer.URL,
		Issuer:      "https://hanzo.id",
		Audiences:   []string{"https://api.hanzo.ai"},
		RequireAuth: true,
	}))
	r.GET("/x", func(c *gin.Context) {
		_, sawHeader = c.Request.Header[http.CanonicalHeaderKey("X-User-Permissions")]
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Attacker also forges a value
	req.Header.Set("X-User-Permissions", "20")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Unparseable claim → no bits granted → header omitted (forged value
	// already stripped on ingress).
	if sawHeader {
		t.Error("SECURITY: unparseable permissions claim must NOT write a header")
	}
}
