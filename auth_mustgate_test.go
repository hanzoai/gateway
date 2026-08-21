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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hanzoai/authz"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
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

// --- One validator: the endpoint pipeline verifies nothing ---
//
// The shipping config used to carry 216 per-endpoint `auth/validator` blocks —
// a second JWT validation, with a second crypto library, against a second key
// source (an in-cluster CLEARTEXT jwk_url with disable_jwk_security), running
// after the edge had already validated the same token. The two disagreed in
// three ways that mattered: audience (the Go edge enforces an ANY-of allowlist;
// go-jose v3 requires ALL, which is why no `audience` could ever be written
// there), the org header (the edge resolves the EFFECTIVE org against the
// token's signed membership, the validator wrote the raw `owner` claim over the
// top of it), and API keys (the edge defers hk-/sk- to the backend that owns
// them, the validator 401'd them).
//
// Now there is one validator — the edge trust boundary — and an endpoint says
// whether it needs an identity with `auth/public`. These tests are what makes
// that checkable rather than asserted.

// shippingConfigs are the configs baked into the image (Dockerfile: COPY
// configs/${CONFIG}/gateway.json). Both are held to the same invariant.
var shippingConfigs = []string{
	"configs/hanzo/gateway.json",
	"configs/lux/gateway.json",
}

func readConfig(t *testing.T, path string) gatewayConfig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var cfg gatewayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cfg
}

type gatewayConfig struct {
	Endpoints []struct {
		Endpoint    string                     `json:"endpoint"`
		Method      string                     `json:"method"`
		ExtraConfig map[string]json.RawMessage `json:"extra_config"`
	} `json:"endpoints"`
}

// TestShippingConfig_NoEndpointValidator is the structural pin: no shipping
// config may declare a JOSE validator or signer at an endpoint. The embedded
// schema refuses the key and the handler chain no longer installs the module,
// so one that appeared would be silently ignored — which is worse than either
// gating or not gating, because it would READ as a gate.
func TestShippingConfig_NoEndpointValidator(t *testing.T) {
	for _, path := range shippingConfigs {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, banned := range []string{`"auth/validator"`, `"auth/signer"`} {
			if bytes.Contains(data, []byte(banned)) {
				t.Errorf("%s declares %s; this gateway runs ONE JWT validator (the edge trust boundary). "+
					"An endpoint declares whether it needs an identity with \"auth/public\", it does not validate a second time.",
					path, banned)
			}
		}
		// The audience landmine that made the second validator unfixable rather
		// than merely redundant: go-jose v3 validates audience with ALL-semantics,
		// so any "audience" there would 401 every single-aud IAM user token.
		// Audience is enforced at the Go edge (ANY-of allowlist) and nowhere else.
		if bytes.Contains(data, []byte(`"audience"`)) {
			t.Errorf(`%s contains an "audience" field; audience belongs to the Go edge allowlist`, path)
		}
		// X-Roles is a RETIRED identity header (authz.Retired): the edge deletes it
		// on ingress and no edge writes it. The endpoint validator's propagate_claims
		// was its last writer, so allowlisting it to a backend now describes a header
		// that provably cannot be present.
		if bytes.Contains(data, []byte(`"X-Roles"`)) {
			t.Errorf("%s forwards X-Roles; it is retired — stripped on ingress and written by nothing", path)
		}
	}
}

// hanzoPublicEndpoints is the surface that answers WITHOUT a credential,
// written out so the diff that changes it is the diff that has to justify it.
//
// It is EXACTLY the set that carried no auth/validator before the collapse, so
// every route that authenticated then authenticates now:
//
//   - the AI inference surface, which takes an hk-/sk- API key the backend
//     resolves (the edge passes those through; the old validator 401'd them,
//     which is why these endpoints could never carry one),
//   - the health probes,
//   - the public catalogs (provider list, pricing policy, analytics heartbeat).
var hanzoPublicEndpoints = map[string]bool{
	"POST /v1/chat":                       true,
	"POST /v1/chat/completions":           true,
	"POST /v1/completions":                true,
	"POST /v1/messages":                   true,
	"GET /v1/models":                      true,
	"GET /ai/{path}":                      true,
	"POST /ai/{path}":                     true,
	"GET /v1/ai/{path}":                   true,
	"POST /v1/ai/{path}":                  true,
	"GET /v1/ai/providers":                true,
	"GET /v1/ai/providers/{owner}/{name}": true,
	"GET /v1/pricing-policy":              true,
	"GET /v1/analytics/heartbeat":         true,
	"GET /health":                         true,
	"GET /":                               true,
	"GET /bot/health":                     true,
	"GET /v1/bot/health":                  true,
	"GET /pubsub/healthz":                 true,
	"GET /v1/pubsub/healthz":              true,
	"GET /v1/ml/health":                   true,
	"GET /v1/train/health":                true,
}

// TestHanzoConfig_PublicSurfaceUnchanged is the behavioural pin on the collapse:
// the set of endpoints reachable without a credential must be exactly the set
// that was reachable without one before. A route that loses its gate shows up
// here as an unexpected public entry; a route that gains one shows up as a
// missing entry (and would 401 traffic that works today).
func TestHanzoConfig_PublicSurfaceUnchanged(t *testing.T) {
	cfg := readConfig(t, "configs/hanzo/gateway.json")

	seen := map[string]bool{}
	for _, ep := range cfg.Endpoints {
		key := ep.Method + " " + ep.Endpoint
		var open bool
		if raw, ok := ep.ExtraConfig["auth/public"]; ok {
			if err := json.Unmarshal(raw, &open); err != nil {
				t.Errorf("%s: auth/public is not a boolean: %s", key, raw)
			}
		}
		if open {
			seen[key] = true
			if !hanzoPublicEndpoints[key] {
				t.Errorf("SECURITY: %s is declared public but authenticated before the collapse", key)
			}
		}
	}
	for key := range hanzoPublicEndpoints {
		if !seen[key] {
			t.Errorf("%s was reachable without a credential before the collapse and is now gated", key)
		}
	}
	if len(cfg.Endpoints) != 237 {
		t.Errorf("endpoint count = %d, want 237 (the routing table is unchanged by this collapse)", len(cfg.Endpoints))
	}
}

// TestLuxConfig_AllPublic pins the Lux edge's surface. It fronts blockchain RPC
// and carried no endpoint credential at all, so every one of its endpoints is
// declared public — which is what preserves its behaviour under a policy whose
// default is to require an identity.
//
// It also makes the exposure legible: POST /v1/admin and GET /v1/metrics reach
// luxd's admin and metrics APIs with no credential. That is what shipped
// before this change and what still ships; it is written down here so it is a
// decision someone can see rather than an omission nobody could.
func TestLuxConfig_AllPublic(t *testing.T) {
	cfg := readConfig(t, "configs/lux/gateway.json")
	if len(cfg.Endpoints) == 0 {
		t.Fatal("lux config declares no endpoints")
	}
	for _, ep := range cfg.Endpoints {
		var open bool
		if raw, ok := ep.ExtraConfig["auth/public"]; ok {
			json.Unmarshal(raw, &open)
		}
		if !open {
			t.Errorf("%s %s is not declared public; the Lux edge gated nothing before and would now 401",
				ep.Method, ep.Endpoint)
		}
	}
}

// --- the requirement itself ---

// TestRequire is the unit pin on the endpoint half of the policy. It reads the
// identity the gate wrote and does nothing else: no key, no parse, no network.
func TestRequire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		userID  string
		want    int // 0 = allow
	}{
		{"verified identity passes", true, "hanzo/alice", 0},
		{"no identity refuses", true, "", http.StatusUnauthorized},
		{"auth disabled requires nothing", false, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.userID != "" {
				h.Set(authz.HeaderUser, tc.userID)
			}
			r := AuthConfig{Enabled: tc.enabled}.require(h)
			switch {
			case tc.want == 0 && r != nil:
				t.Fatalf("refused with %d, want allow", r.Status)
			case tc.want != 0 && r == nil:
				t.Fatalf("allowed, want %d", tc.want)
			case r != nil && r.Status != tc.want:
				t.Fatalf("status = %d, want %d", r.Status, tc.want)
			}
		})
	}
}

// TestRequireIdentity_EndToEnd drives the two halves over ONE request, which is
// the only way to show they cannot disagree: the gate verifies the token and
// writes the identity, the endpoint reads that identity. Nothing between them
// validates anything.
func TestRequireIdentity_EndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tj := newTestJWKS(t)
	jwks := tj.serveJWKS(t)
	defer jwks.Close()

	authCfg := AuthConfig{
		Enabled:   true,
		JWKSURL:   jwks.URL,
		Issuer:    "https://hanzo.id",
		Audiences: []string{"https://api.hanzo.ai"},
	}

	reached := map[string]bool{}
	served := func(name string) router.HandlerFactory {
		return func(*config.EndpointConfig, proxy.Proxy) gin.HandlerFunc {
			return func(c *gin.Context) { reached[name] = true; c.Status(http.StatusOK) }
		}
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(authCfg))
	r.GET("/v1/kms/secrets", requireIdentity(served("gated"), logging.NoOp, authCfg)(
		&config.EndpointConfig{Endpoint: "/v1/kms/secrets"}, nil))
	r.POST("/v1/chat/completions", requireIdentity(served("public"), logging.NoOp, authCfg)(
		&config.EndpointConfig{
			Endpoint:    "/v1/chat/completions",
			ExtraConfig: config.ExtraConfig{authPublic: true},
		}, nil))

	do := func(method, path, credential string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.Host = "api.hanzo.ai"
		if credential != "" {
			req.Header.Set("Authorization", credential)
		}
		r.ServeHTTP(w, req)
		return w
	}
	token := tj.signToken(t, validClaims("https://hanzo.id", "https://api.hanzo.ai"))

	if w := do(http.MethodGet, "/v1/kms/secrets", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("gated endpoint, no credential: status = %d, want 401", w.Code)
	}
	if reached["gated"] {
		t.Error("SECURITY: a tokenless request reached a gated backend")
	}
	if w := do(http.MethodGet, "/v1/kms/secrets", "Bearer "+token); w.Code != http.StatusOK {
		t.Errorf("gated endpoint, valid JWT: status = %d, want 200 (body %s)", w.Code, w.Body)
	}

	// An API key carries no IAM identity by design — the backend that issued it
	// resolves it. A route that needs an identity refuses it, exactly as the
	// endpoint validator did.
	if w := do(http.MethodGet, "/v1/kms/secrets", "Bearer hk-live-abcdef"); w.Code != http.StatusUnauthorized {
		t.Errorf("gated endpoint, API key: status = %d, want 401", w.Code)
	}

	// The AI surface is where that API key is meant to go, and it is public for
	// exactly that reason.
	if w := do(http.MethodPost, "/v1/chat/completions", "Bearer hk-live-abcdef"); w.Code != http.StatusOK {
		t.Errorf("public endpoint, API key: status = %d, want 200", w.Code)
	}
	if w := do(http.MethodPost, "/v1/chat/completions", ""); w.Code != http.StatusOK {
		t.Errorf("public endpoint, no credential: status = %d, want 200", w.Code)
	}
	if !reached["public"] {
		t.Error("public endpoint never reached its backend")
	}
}

// TestRequireIdentity_ForgedIdentityCannotSatisfyIt is the pin that the
// requirement is not a header check a client can pass. The gate deletes every
// identity header on ingress, so a forged X-User-Id is gone before the endpoint
// looks for one — which is why reading the header is safe here and would not be
// anywhere else.
func TestRequireIdentity_ForgedIdentityCannotSatisfyIt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tj := newTestJWKS(t)
	jwks := tj.serveJWKS(t)
	defer jwks.Close()

	authCfg := AuthConfig{
		Enabled:   true,
		JWKSURL:   jwks.URL,
		Issuer:    "https://hanzo.id",
		Audiences: []string{"https://api.hanzo.ai"},
	}

	var reached bool
	hf := func(*config.EndpointConfig, proxy.Proxy) gin.HandlerFunc {
		return func(c *gin.Context) { reached = true; c.Status(http.StatusOK) }
	}

	r := gin.New()
	r.Use(NewAuthMiddleware(authCfg))
	r.GET("/v1/kms/secrets", requireIdentity(hf, logging.NoOp, authCfg)(
		&config.EndpointConfig{Endpoint: "/v1/kms/secrets"}, nil))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/kms/secrets", nil)
	req.Host = "api.hanzo.ai"
	req.Header.Set(authz.HeaderUser, "hanzo/attacker")
	req.Header.Set(authz.HeaderOrg, "victim-org")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("forged identity: status = %d, want 401", w.Code)
	}
	if reached {
		t.Error("SECURITY: a forged X-User-Id satisfied the endpoint credential requirement")
	}
}
