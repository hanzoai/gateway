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
	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"valid bearer", "Bearer eyJhbGciOi...", "eyJhbGciOi..."},
		{"lowercase bearer", "bearer eyJhbGciOi...", "eyJhbGciOi..."},
		{"no bearer prefix", "Basic dXNlcjpwYXNz", ""},
		{"empty header", "", ""},
		{"bearer only", "Bearer", ""},
		{"bearer with spaces", "Bearer  eyJhbGciOi... ", "eyJhbGciOi..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got := edge.Bearer(req.Header)
			if got != tt.expected {
				t.Errorf("extractBearerToken() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractTokenFromCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		value      string
		expected   string
	}{
		{"iam cookie", "iam_access_token", "tok123", "tok123"},
		{"access_token cookie", "access_token", "tok456", "tok456"},
		{"hanzo_token cookie", "hanzo_token", "tok789", "tok789"},
		{"unknown cookie", "random_cookie", "tokXYZ", ""},
		{"empty cookie", "iam_access_token", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.value != "" {
				req.AddCookie(&http.Cookie{Name: tt.cookieName, Value: tt.value})
			}
			got := edge.Cookie(req.Header)
			if got != tt.expected {
				t.Errorf("extractTokenFromCookie() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestAuthMiddlewarePublicPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{"/healthz", "/.well-known/"},
		PublicHosts: []string{"hanzo.id"},
		RequireAuth: true, // Even with require=true, public paths should pass
	}

	middleware := NewAuthMiddleware(cfg)

	tests := []struct {
		name           string
		path           string
		host           string
		expectedStatus int
	}{
		{"health check bypasses auth", "/healthz", "api.hanzo.ai", http.StatusOK},
		{"well-known bypasses auth", "/.well-known/jwks", "api.hanzo.ai", http.StatusOK},
		{"public host bypasses auth", "/api/anything", "hanzo.id", http.StatusOK},
		{"non-public path requires auth", "/api/chat/completions", "api.hanzo.ai", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			r.Use(middleware)
			r.GET(tt.path, func(c *gin.Context) {
				c.Status(http.StatusOK)
			})
			// Also handle POST for api paths
			r.POST(tt.path, func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			c.Request = httptest.NewRequest(http.MethodGet, tt.path, nil)
			c.Request.Host = tt.host

			r.ServeHTTP(w, c.Request)

			if w.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.expectedStatus)
			}
		})
	}
}

func TestAuthMiddlewareNoTokenOptional(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{},
		RequireAuth: false, // Don't require auth
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotOrgHeader string
	r.Use(middleware)
	r.GET("/api/test", func(c *gin.Context) {
		gotOrgHeader = c.Request.Header.Get("X-Org-Id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for optional auth without token, got %d", w.Code)
	}
	if gotOrgHeader != "" {
		t.Errorf("expected no X-Org-Id header without token, got %q", gotOrgHeader)
	}
}

func TestIsAPIKey(t *testing.T) {
	tests := []struct {
		token    string
		expected bool
	}{
		{"hk-0d2eb9cfafd049389f2904cad770a9d8", true},
		{"sk-ant-api03-cPXAHvR", true},
		{"sk-live-abc123", true},
		{"fw_6UVdtest", true},
		{"hz_widget_public", true},
		{"hz_custom_key_123", true},
		{"pk-publishable-key", true},
		{"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig", false},
		{"random-token", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := authz.IsAPIKey(tt.token); got != tt.expected {
			t.Errorf("authz.IsAPIKey(%q) = %v, want %v", tt.token, got, tt.expected)
		}
	}
}

func TestAuthMiddlewareAPIKeyPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{},
		RequireAuth: true,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer sk-0d2eb9cfafd049389f2904cad770a9d8")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("API key should pass through auth middleware, got %d", w.Code)
	}
}

func TestAuthMiddlewareWidgetKeyPassthrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{},
		RequireAuth: true,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer hz_widget_public")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("widget key should pass through auth middleware, got %d", w.Code)
	}
}

func TestDefaultAuthConfig(t *testing.T) {
	cfg := DefaultAuthConfig()

	if !cfg.Enabled {
		t.Error("Enabled should default to true")
	}
	if cfg.JWKSURL == "" {
		t.Error("JWKSURL should not be empty")
	}
	if cfg.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if len(cfg.PublicPaths) == 0 {
		t.Error("PublicPaths should have defaults")
	}
	if len(cfg.PublicHosts) == 0 {
		t.Error("PublicHosts should have defaults")
	}
	if cfg.RequireAuth {
		t.Error("RequireAuth should default to false")
	}
}

func TestAuthMiddlewareDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     false,
		RequireAuth: true,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	r.Use(middleware)
	r.GET("/api/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("disabled auth should pass through all requests, got %d", w.Code)
	}
}

// TestStripIdentityHeaders verifies the stripIdentityHeaders function directly.
func TestStripIdentityHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Org-Id", "attacker-org")
	req.Header.Set("X-User-Id", "attacker-user")
	req.Header.Set("X-User-Email", "attacker@evil.com")

	edge.Strip(req.Header)

	for _, h := range []string{"X-Org-Id", "X-User-Id", "X-User-Email"} {
		if v := req.Header.Get(h); v != "" {
			t.Errorf("stripIdentityHeaders did not remove %s, got %q", h, v)
		}
	}
}

// TestHeaderInjectionPublicHost verifies that client-supplied X-Identity-* headers
// are stripped when the request hits a public host bypass path.
// This is a regression test for CVE: identity header injection.
func TestHeaderInjectionPublicHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{"hanzo.id"},
		RequireAuth: false,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotOrg, gotUser, gotEmail string
	r.Use(middleware)
	r.GET("/api/anything", func(c *gin.Context) {
		gotOrg = c.Request.Header.Get("X-Org-Id")
		gotUser = c.Request.Header.Get("X-User-Id")
		gotEmail = c.Request.Header.Get("X-User-Email")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Host = "hanzo.id"
	// Attacker injects identity headers
	req.Header.Set("X-Org-Id", "admin")
	req.Header.Set("X-User-Id", "root")
	req.Header.Set("X-User-Email", "admin@hanzo.ai")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotOrg != "" {
		t.Errorf("X-Org-Id should be stripped on public host, got %q", gotOrg)
	}
	if gotUser != "" {
		t.Errorf("X-User-Id should be stripped on public host, got %q", gotUser)
	}
	if gotEmail != "" {
		t.Errorf("X-User-Email should be stripped on public host, got %q", gotEmail)
	}
}

// TestHeaderInjectionPublicPath verifies that client-supplied X-Identity-* headers
// are stripped when the request hits a public path bypass.
func TestHeaderInjectionPublicPath(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{"/healthz"},
		PublicHosts: []string{},
		RequireAuth: false,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotOrg string
	r.Use(middleware)
	r.GET("/healthz", func(c *gin.Context) {
		gotOrg = c.Request.Header.Get("X-Org-Id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("X-Org-Id", "forged-org")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotOrg != "" {
		t.Errorf("X-Org-Id should be stripped on public path, got %q", gotOrg)
	}
}

// TestHeaderInjectionNoToken verifies that client-supplied X-Identity-* headers
// are stripped when no token is present and auth is optional.
func TestHeaderInjectionNoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{},
		RequireAuth: false,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotUser string
	r.Use(middleware)
	r.GET("/api/test", func(c *gin.Context) {
		gotUser = c.Request.Header.Get("X-User-Id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	// No Authorization header, but attacker injects identity
	req.Header.Set("X-User-Id", "forged-admin")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotUser != "" {
		t.Errorf("X-User-Id should be stripped with no token, got %q", gotUser)
	}
}

// TestHeaderInjectionAPIKey verifies that client-supplied X-Identity-* headers
// are stripped when an API key bypasses JWT validation.
func TestHeaderInjectionAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled:     true,
		JWKSURL:     "https://hanzo.id/v1/iam/.well-known/jwks",
		Issuer:      "https://hanzo.id",
		PublicPaths: []string{},
		PublicHosts: []string{},
		RequireAuth: true,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotOrg, gotUser string
	r.Use(middleware)
	r.POST("/v1/chat/completions", func(c *gin.Context) {
		gotOrg = c.Request.Header.Get("X-Org-Id")
		gotUser = c.Request.Header.Get("X-User-Id")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer sk-ant-api03-cPXAHvR")
	// Attacker also injects identity headers alongside API key
	req.Header.Set("X-Org-Id", "forged-org")
	req.Header.Set("X-User-Id", "forged-admin")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotOrg != "" {
		t.Errorf("X-Org-Id should be stripped on API key path, got %q", gotOrg)
	}
	if gotUser != "" {
		t.Errorf("X-User-Id should be stripped on API key path, got %q", gotUser)
	}
}

// TestHeaderInjectionDisabledAuth verifies that client-supplied X-Identity-*
// headers are stripped even when auth is entirely disabled.
func TestHeaderInjectionDisabledAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := AuthConfig{
		Enabled: false,
	}

	middleware := NewAuthMiddleware(cfg)

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)

	var gotOrg, gotUser, gotEmail string
	r.Use(middleware)
	r.GET("/api/test", func(c *gin.Context) {
		gotOrg = c.Request.Header.Get("X-Org-Id")
		gotUser = c.Request.Header.Get("X-User-Id")
		gotEmail = c.Request.Header.Get("X-User-Email")
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("X-Org-Id", "forged-org")
	req.Header.Set("X-User-Id", "forged-admin")
	req.Header.Set("X-User-Email", "admin@evil.com")

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotOrg != "" {
		t.Errorf("X-Org-Id should be stripped even when auth disabled, got %q", gotOrg)
	}
	if gotUser != "" {
		t.Errorf("X-User-Id should be stripped even when auth disabled, got %q", gotUser)
	}
	if gotEmail != "" {
		t.Errorf("X-User-Email should be stripped even when auth disabled, got %q", gotEmail)
	}
}

// TestDefaultAuthConfigAudience verifies the default config carries the
// audience allowlist: the gateway origin plus the known IAM client_ids
// (IAM stamps user tokens with aud=<client_id>, never the origin).
func TestDefaultAuthConfigAudience(t *testing.T) {
	cfg := DefaultAuthConfig()
	if len(cfg.Audiences) == 0 {
		t.Fatal("Audiences should default to a non-empty allowlist")
	}
	has := func(want string) bool {
		for _, a := range cfg.Audiences {
			if a == want {
				return true
			}
		}
		return false
	}
	// The gateway origin and at least the primary app client_id must be
	// accepted, else every normal user JWT (aud=hanzo-app) is rejected.
	for _, want := range []string{"https://api.hanzo.ai", "hanzo-app"} {
		if !has(want) {
			t.Errorf("default Audiences %v missing %q", cfg.Audiences, want)
		}
	}
}

func TestBillingCheckerFailClosed(t *testing.T) {
	// Unreachable billing service -> deny (no free), with a non-nil error so
	// the caller can surface a 503 rather than a wrong "insufficient balance".
	checker := newBillingChecker("http://127.0.0.1:1", "test-token") // unreachable port
	ok, err := checker.checkBalance("hanzo/test-user")
	if ok {
		t.Error("billing check must fail-closed (deny) when commerce is unreachable")
	}
	if err == nil {
		t.Error("unreachable commerce should return a non-nil error so the caller emits 503")
	}
}

func TestBillingCheckerNoURL(t *testing.T) {
	// Test with empty billing URL - should pass through
	checker := newBillingChecker("", "")
	ok, err := checker.checkBalance("hanzo/test-user")
	if !ok {
		t.Error("billing check should pass when no URL configured")
	}
	if err != nil {
		t.Errorf("billing check should not error when no URL configured: %v", err)
	}
}
