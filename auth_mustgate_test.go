// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// gin-driven: this suite drives the LEGACY Lura edge's transports
// (legacy_transports.go), which exist only under this tag. The policies it
// exercises are framework-free values shared with the zip edge, and
// transport_parity_test.go asserts the two edges answer alike.

package gateway

// Must-gate hardening regression tests (PR #34 follow-up).
//
// These lock in the edge-correctness fixes that pair with the gateway.json
// auth/validator surface: the /v1/commerce funding surface is never
// balance-gated, billing refuses to run half-configured, forged X-Project-Id
// never reaches a backend, and audience is enforced at the Go edge (ANY-of
// allowlist) — NOT in the config-declared auth/validator, whose go-jose v3 backend
// uses ALL-semantics and would 401 every single-aud user JWT.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

// --- Finding #2: the /v1/commerce funding surface is NEVER balance-gated ---

func TestBillingPathMatch_ExcludesCommerce(t *testing.T) {
	prefixes := []string{"/v1/commerce", "/v1/cloud", "/v1/mpc"}

	// Funding surface and its sub-paths: never gated, even though listed in
	// BILLING_PATHS. A 402/503 here would trap a zero-balance user out of the
	// only page that lets them add funds.
	for _, p := range []string{
		"/v1/commerce",
		"/v1/commerce/",
		"/v1/commerce/billing/topup",
		"/v1/commerce/checkout",
	} {
		if billingPathMatch(p, prefixes) {
			t.Errorf("billingPathMatch(%q, withCommerce) = true; funding surface must never be balance-gated", p)
		}
	}

	// Excluded even under empty BILLING_PATHS (enforce-everywhere) scope.
	if billingPathMatch("/v1/commerce/topup", nil) {
		t.Error("billingPathMatch(commerce, emptyPaths) = true; funding surface must never be balance-gated")
	}

	// Metered siblings remain gated (the exclusion is scoped to commerce, not
	// a blanket disable).
	for _, p := range []string{"/v1/cloud/deploy", "/v1/mpc/keys"} {
		if !billingPathMatch(p, prefixes) {
			t.Errorf("billingPathMatch(%q) = false; metered surface must be gated", p)
		}
	}
}

// --- Finding #3: billing refuses to run half-configured (fail fast/closed) ---

func TestAuthConfig_Validate(t *testing.T) {
	configured := AuthConfig{
		BillingEnabled: true,
		BillingURL:     "http://commerce.hanzo.svc.cluster.local:8001",
		BillingToken:   "svc-token",
	}
	if err := configured.Validate(); err != nil {
		t.Errorf("fully-configured billing should validate, got %v", err)
	}

	noToken := configured
	noToken.BillingToken = ""
	if err := noToken.Validate(); err == nil {
		t.Error("billing enabled without COMMERCE_SERVICE_TOKEN must fail validation")
	}

	noURL := configured
	noURL.BillingURL = ""
	if err := noURL.Validate(); err == nil {
		t.Error("billing enabled without AUTH_BILLING_URL must fail validation")
	}

	if err := (AuthConfig{BillingEnabled: false}).Validate(); err != nil {
		t.Errorf("billing disabled should always validate, got %v", err)
	}
}

// When billing is enabled but its Commerce dependency is missing, the metered
// surface fails CLOSED (503) — never open — while the funding surface stays
// reachable so the user can still pay.
func TestAuthMiddleware_BillingMisconfiguredFailsClosed(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, func(c *AuthConfig) {
		c.BillingEnabled = true
		c.BillingURL = "http://commerce.invalid:8001"
		c.BillingToken = "" // misconfigured: no service token
		c.BillingPaths = []string{"/v1/cloud", "/v1/commerce"}
	})
	defer jwksServer.Close()

	r.GET("/v1/cloud/usage", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/v1/commerce/balance", func(c *gin.Context) { c.Status(http.StatusOK) })

	token := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai"))

	// Metered path -> 503 (fail closed; must never fail open to 200).
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/cloud/usage", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("misconfigured billing on metered path should 503 (fail closed), got %d", w.Code)
	}

	// Funding surface -> reachable (200), never balance-gated.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/commerce/balance", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("funding surface must stay reachable when billing misconfigured, got %d", w.Code)
	}
}

// --- Finding #5: a forged X-Project-Id never reaches a backend ---

func TestValidAuth_StripsForgedXProjectId(t *testing.T) {
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, nil)
	defer jwksServer.Close()

	var gotProject string
	r.GET("/v1/cloud/usage", func(c *gin.Context) {
		gotProject = c.Request.Header.Get("X-Project-Id")
		c.Status(http.StatusOK)
	})

	token := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai"))
	req := httptest.NewRequest(http.MethodGet, "/v1/cloud/usage", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Project-Id", "victim-project") // forged scope selector

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("valid JWT should get 200, got %d", w.Code)
	}
	if gotProject != "" {
		t.Errorf("SECURITY: forged X-Project-Id reached backend = %q; the edge writes no project header, so it must be stripped", gotProject)
	}
}

// --- Finding #4: audience is an ANY-of allowlist enforced at the Go edge ---

// TestJWTAuth_AudienceAllowlist_AnySemantics proves the edge accepts a token
// whose single aud is ANY listed value and rejects one outside the list. This
// is exactly why audience is enforced here and not in the config-declared
// auth/validator: the JOSE validator module (go-jose v3) requires the token to contain ALL
// configured audiences, so a multi-entry list there would reject every
// single-aud IAM user token.
func TestJWTAuth_AudienceAllowlist_AnySemantics(t *testing.T) {
	allow := []string{"hanzo-app", "hanzo-console", "hanzo-chat", "https://api.hanzo.ai"}
	r, tj, jwksServer := setupMiddlewareWithJWKS(t, func(c *AuthConfig) {
		c.Audiences = allow
	})
	defer jwksServer.Close()

	r.GET("/api/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, aud := range allow {
		w := httptest.NewRecorder()
		token := tj.signToken(t, validClaims("https://hanzo.id", aud))
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Host = "api.hanzo.ai"
		req.Header.Set("Authorization", "Bearer "+token)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("token with single aud=%q (in allowlist) should pass, got %d", aud, w.Code)
		}
	}

	w := httptest.NewRecorder()
	token := tj.signToken(t, validClaims("https://hanzo.id", "evil-client"))
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("token with aud outside the allowlist should 401, got %d", w.Code)
	}
}

// TestGatewayConfig_NoJWTAudience is the availability guard for the
// audience landmine. the JOSE validator module validates audience with ALL-semantics — a
// token must carry EVERY configured aud. IAM stamps a single aud=<client_id>
// per token, so any "audience" on a config-declared auth/validator block would 401
// every user JWT. Audience belongs at the Go edge (ANY-of allowlist). Keep the
// gateway config audience-free.
func TestGatewayConfig_NoJWTAudience(t *testing.T) {
	data, err := os.ReadFile("configs/hanzo/gateway.json")
	if err != nil {
		t.Skipf("gateway.json not readable from package dir: %v", err)
	}
	if bytes.Contains(data, []byte(`"audience"`)) {
		t.Fatal(`configs/hanzo/gateway.json contains an "audience" field; the JOSE validator module ALL-semantics would 401 every single-aud user JWT. Enforce audience at the Go edge instead.`)
	}
}
