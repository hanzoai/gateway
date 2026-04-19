package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gin-gonic/gin"
)

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	// Enabled controls whether the auth middleware is active.
	// Default: true. Set to false via AUTH_ENABLED=false to disable
	// all auth checks (useful for integration tests and development).
	Enabled bool

	// JWKS URL to fetch signing keys (default: https://hanzo.id/.well-known/jwks)
	JWKSURL string

	// Expected JWT issuer (default: https://hanzo.id)
	Issuer string

	// Expected JWT audience (default: https://api.hanzo.ai)
	Audience string

	// Billing check endpoint (default: http://commerce.hanzo.svc.cluster.local:8001)
	BillingURL string

	// BillingToken is the COMMERCE_SERVICE_TOKEN for authenticating with Commerce.
	BillingToken string

	// BillingEnabled controls whether billing checks are performed.
	// Default: true (checks enabled). Set to false to disable.
	BillingEnabled bool

	// Paths that bypass auth entirely (exact prefix match)
	PublicPaths []string

	// Hosts that bypass auth entirely (e.g. hanzo.id for login)
	PublicHosts []string

	// If true, requests without a token are rejected (402/401).
	// If false (default), requests without a token pass through without headers.
	RequireAuth bool
}

// hanzoJWTClaims represents the JWT claims from Casdoor/hanzo.id.
type hanzoJWTClaims struct {
	jwt.Claims

	// Casdoor puts the org slug in "owner"
	Owner string `json:"owner"`
	// User display name
	Name string `json:"name"`
	// Preferred username (Casdoor uses this when sub is empty)
	PreferredUsername string `json:"preferred_username"`
	// Email
	Email string `json:"email"`
	// Phone number (E.164 format from IAM)
	Phone string `json:"phone"`
	// OIDC standard phone_number claim
	PhoneNumber string `json:"phone_number"`
	// User type
	Type string `json:"type"`
	// IAM admin flag
	IsAdmin bool `json:"isAdmin"`
	// Roles array (Casdoor emits []*Role objects with name/displayName,
	// or a plain []string — tolerate both and join names with commas).
	Roles json.RawMessage `json:"roles"`
}

// extractRoleNames converts the raw "roles" claim (either []string or
// []{"name":"..."}) into a comma-joined list of role names.
// Returns "" if the claim is empty/absent or unparseable.
func extractRoleNames(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try []string first
	var asStrings []string
	if err := json.Unmarshal(raw, &asStrings); err == nil {
		return strings.Join(asStrings, ",")
	}
	// Then []map[string]any (Casdoor Role objects)
	var asObjects []map[string]any
	if err := json.Unmarshal(raw, &asObjects); err == nil {
		names := make([]string, 0, len(asObjects))
		for _, o := range asObjects {
			if n, ok := o["name"].(string); ok && n != "" {
				names = append(names, n)
			}
		}
		return strings.Join(names, ",")
	}
	return ""
}

// jwksCache caches JWKS keys with TTL-based refresh.
type jwksCache struct {
	mu        sync.RWMutex
	keys      *gojose.JSONWebKeySet
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

func newJWKSCache(url string, ttl time.Duration) *jwksCache {
	return &jwksCache{
		url: url,
		ttl: ttl,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *jwksCache) getKeys() (*gojose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		keys := c.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.keys, nil
	}

	keys, err := c.fetchJWKS()
	if err != nil {
		// If we have stale keys, return those rather than failing
		if c.keys != nil {
			return c.keys, nil
		}
		return nil, err
	}

	c.keys = keys
	c.fetchedAt = time.Now()
	return keys, nil
}

func (c *jwksCache) fetchJWKS() (*gojose.JSONWebKeySet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to read body: %w", err)
	}

	var jwks gojose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("jwks: failed to parse: %w", err)
	}

	return &jwks, nil
}

// billingChecker checks user billing status against Commerce API.
//
// Commerce endpoints used:
//   GET /api/v1/billing/balance?user={user}&currency=usd
//     -> { "user": "...", "currency": "usd", "balance": 5000, "holds": 0, "available": 5000 }
//
// All amounts are in cents. available = balance - holds.
// A user can proceed if available > 0.
type billingChecker struct {
	baseURL string
	token   string // COMMERCE_SERVICE_TOKEN for S2S auth
	client  *http.Client
}

type billingResponse struct {
	User      string `json:"user"`
	Currency  string `json:"currency"`
	Balance   int64  `json:"balance"`
	Holds     int64  `json:"holds"`
	Available int64  `json:"available"`
}

func newBillingChecker(baseURL, token string) *billingChecker {
	return &billingChecker{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// checkBalance returns true if the user has positive available balance or if
// the check fails (fail-open). The user identifier is the IAM user ID
// (e.g., "hanzo/alice" or the JWT subject).
//
// FAIL-OPEN: If Commerce is unreachable, returns an error, or returns a
// non-200 status, the request is ALLOWED through. We never block users
// due to billing infrastructure failures.
func (b *billingChecker) checkBalance(userID string) (bool, error) {
	if b.baseURL == "" {
		return true, nil // No billing configured, allow through
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := fmt.Sprintf("%s/api/v1/billing/balance?user=%s&currency=usd", b.baseURL, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return true, err // Fail-open
	}

	// Authenticate with Commerce service token
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return true, err // Fail-open: billing service unreachable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return true, nil // Fail-open: billing service error
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return true, err // Fail-open
	}

	var result billingResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return true, err // Fail-open
	}

	return result.Available > 0, nil
}

// DefaultAuthConfig returns the default auth configuration from environment variables.
func DefaultAuthConfig() AuthConfig {
	enabled := true
	if os.Getenv("AUTH_ENABLED") == "false" {
		enabled = false
	}

	jwksURL := os.Getenv("AUTH_JWKS_URL")
	if jwksURL == "" {
		jwksURL = "https://hanzo.id/.well-known/jwks"
	}

	issuer := os.Getenv("AUTH_ISSUER")
	if issuer == "" {
		issuer = "https://hanzo.id"
	}

	// AUTH_AUDIENCE is optional. When not set, audience validation is skipped
	// (issuer + JWKS signature is sufficient when all apps share the same IAM).
	audience := os.Getenv("AUTH_AUDIENCE")

	billingURL := os.Getenv("AUTH_BILLING_URL")
	if billingURL == "" {
		billingURL = "http://commerce.hanzo.svc.cluster.local:8001"
	}

	billingToken := os.Getenv("COMMERCE_SERVICE_TOKEN")

	billingEnabled := true
	if os.Getenv("BILLING_ENABLED") == "false" {
		billingEnabled = false
	}

	publicPathsStr := os.Getenv("AUTH_PUBLIC_PATHS")
	var publicPaths []string
	if publicPathsStr != "" {
		publicPaths = strings.Split(publicPathsStr, ",")
		for i := range publicPaths {
			publicPaths[i] = strings.TrimSpace(publicPaths[i])
		}
	} else {
		// Default public paths
		publicPaths = []string{
			"/healthz",
			"/__stats",
			"/.well-known/",
			"/favicon",
		}
	}

	publicHostsStr := os.Getenv("AUTH_PUBLIC_HOSTS")
	var publicHosts []string
	if publicHostsStr != "" {
		publicHosts = strings.Split(publicHostsStr, ",")
		for i := range publicHosts {
			publicHosts[i] = strings.TrimSpace(publicHosts[i])
		}
	} else {
		// Default public hosts: IAM/login domains don't need gateway auth
		publicHosts = []string{
			"hanzo.id",
			"lux.id",
			"pars.id",
			"id.bootno.de",
			"id.zoo.network",
			"iam.hanzo.ai",
		}
	}

	requireAuth := os.Getenv("AUTH_REQUIRE") == "true"

	return AuthConfig{
		Enabled:        enabled,
		JWKSURL:        jwksURL,
		Issuer:         issuer,
		Audience:       audience,
		BillingURL:     billingURL,
		BillingToken:   billingToken,
		BillingEnabled: billingEnabled,
		PublicPaths:    publicPaths,
		PublicHosts:    publicHosts,
		RequireAuth:    requireAuth,
	}
}

// NewAuthMiddleware creates a gin middleware that validates IAM JWT tokens,
// checks billing status, and injects identity headers for downstream services.
//
// Canonical identity headers (the only 3 downstream services should rely on):
//   - X-User-Id:      user ID from JWT "sub" (fallback: preferred_username, name)
//   - X-Org-Id:       org slug from JWT "owner" claim
//   - X-Roles:        comma-joined role names from JWT "roles" claim
//
// Auxiliary headers (derivatives of the JWT for convenience):
//   - X-User-Email:   email from JWT "email" claim
//   - X-Phone-Number: phone from JWT "phone_number" or "phone" claim
//   - X-User-IsAdmin: "true" if the JWT asserts isAdmin
//
// Billing:
//   - Checks commerce service for positive balance
//   - Fail-open: if billing service is unreachable, request proceeds
//   - If balance <= 0: returns 402 Payment Required
//
// Public endpoints (configurable allowlist) bypass all auth checks.
func NewAuthMiddleware(cfg AuthConfig) gin.HandlerFunc {
	// When auth is disabled (AUTH_ENABLED=false), pass all requests through
	// without any token validation or billing checks. Still strip identity
	// headers — even in dev/test, downstream services must not trust
	// client-supplied identity.
	if !cfg.Enabled {
		return func(c *gin.Context) {
			stripIdentityHeaders(c.Request)
			c.Next()
		}
	}

	cache := newJWKSCache(cfg.JWKSURL, 5*time.Minute)
	billing := newBillingChecker(cfg.BillingURL, cfg.BillingToken)

	// Pre-build public host set for O(1) lookup
	publicHostSet := make(map[string]bool, len(cfg.PublicHosts))
	for _, h := range cfg.PublicHosts {
		publicHostSet[h] = true
	}

	return func(c *gin.Context) {
		// SECURITY: Unconditionally strip client-supplied identity headers.
		// Only the gateway is authorized to set these after JWT validation.
		// This MUST be the first action before any bypass path (public hosts,
		// public paths, API keys, no-token pass-through).
		stripIdentityHeaders(c.Request)

		host := strings.Split(c.Request.Host, ":")[0]
		path := c.Request.URL.Path

		// Skip auth for public hosts (IAM/login domains)
		if publicHostSet[host] {
			c.Next()
			return
		}

		// Skip auth for public paths
		for _, pp := range cfg.PublicPaths {
			if strings.HasPrefix(path, pp) {
				c.Next()
				return
			}
		}

		// Extract token from Authorization header or cookie
		token := extractBearerToken(c.Request)
		if token == "" {
			token = extractTokenFromCookie(c.Request)
		}

		if token == "" {
			if cfg.RequireAuth {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Authentication required",
				})
				return
			}
			// No token, pass through without identity headers
			c.Next()
			return
		}

		// API keys (hk-*, sk-*, fw_*, hz_*, pk-*) are validated by the
		// backend services directly (cloud-api, commerce, etc.), not by
		// the gateway. Pass them through without JWT validation.
		if isAPIKey(token) {
			c.Next()
			return
		}

		// Parse and validate JWT
		claims, err := validateToken(token, cache, cfg.Issuer, cfg.Audience)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Invalid token",
				"detail":  err.Error(),
			})
			return
		}

		orgID := claims.Owner
		userID := claims.Subject
		// Casdoor leaves "sub" empty — fall back to preferred_username then name
		if userID == "" {
			userID = claims.PreferredUsername
		}
		if userID == "" {
			userID = claims.Name
		}
		userEmail := claims.Email
		// Phone: prefer OIDC phone_number, fall back to Casdoor's phone field
		userPhone := claims.PhoneNumber
		if userPhone == "" {
			userPhone = claims.Phone
		}

		// Inject the canonical 3 identity headers for downstream services.
		// X-User-Id <- sub, X-Org-Id <- owner, X-Roles <- roles (comma-joined).
		// Auxiliary headers (email, phone, isAdmin) are strictly derivative
		// of the JWT and may be consumed by services that need them.
		c.Request.Header.Set("X-User-Id", userID)
		c.Request.Header.Set("X-Org-Id", orgID)
		if roles := extractRoleNames(claims.Roles); roles != "" {
			c.Request.Header.Set("X-Roles", roles)
		}
		c.Request.Header.Set("X-User-Email", userEmail)
		if userPhone != "" {
			c.Request.Header.Set("X-Phone-Number", userPhone)
		}
		// Propagate isAdmin for downstream RBAC (broker compliance, etc.)
		if claims.IsAdmin {
			c.Request.Header.Set("X-User-IsAdmin", "true")
		}

		// Check billing status (fail-open)
		// Uses userID (JWT subject) as the billing identity, which maps to
		// Commerce's user-scoped balance tracking.
		if cfg.BillingEnabled && userID != "" {
			// Construct the Commerce user identifier: org/username
			billingUser := userID
			if orgID != "" && !strings.Contains(userID, "/") {
				billingUser = orgID + "/" + userID
			}

			hasBalance, _ := billing.checkBalance(billingUser)
			if !hasBalance {
				c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
					"error":   "insufficient_balance",
					"message": "Your account has insufficient balance. Please add funds at the platform billing page",
					"user":    billingUser,
				})
				return
			}
		}

		c.Next()
	}
}

// validateToken parses and validates a JWT token using the cached JWKS.
func validateToken(rawToken string, cache *jwksCache, expectedIssuer string, expectedAudience string) (*hanzoJWTClaims, error) {
	tok, err := jwt.ParseSigned(rawToken, []gojose.SignatureAlgorithm{
		gojose.RS256, gojose.RS384, gojose.RS512,
		gojose.ES256, gojose.ES384, gojose.ES512,
		gojose.PS256, gojose.PS384, gojose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	keys, err := cache.getKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Try each key from the JWKS that matches the token's key ID
	var claims hanzoJWTClaims
	var lastErr error

	for _, header := range tok.Headers {
		if header.KeyID != "" {
			matchingKeys := keys.Key(header.KeyID)
			for _, key := range matchingKeys {
				pubKey := key.Key
				if err := tok.Claims(pubKey, &claims); err == nil {
					goto validated
				} else {
					lastErr = err
				}
			}
		}
	}

	// If no key ID match, try all keys
	for _, key := range keys.Keys {
		if key.Use == "sig" || key.Use == "" {
			pubKey := key.Key
			// Only try RSA or EC public keys
			switch pubKey.(type) {
			case *rsa.PublicKey:
				if err := tok.Claims(pubKey, &claims); err == nil {
					goto validated
				} else {
					lastErr = err
				}
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("no matching key found: %w", lastErr)
	}
	return nil, fmt.Errorf("no matching key found in JWKS")

validated:
	// Reject tokens with no issuer claim. An empty issuer would cause
	// ValidateWithLeeway to skip issuer comparison entirely, allowing
	// tokens from any (or no) issuer to pass validation.
	if claims.Claims.Issuer == "" {
		return nil, fmt.Errorf("invalid token: missing issuer")
	}

	// Validate standard claims: issuer, audience, and expiry.
	// Issuer and audience are ALWAYS validated — a token missing these
	// claims or carrying wrong values is rejected unconditionally.
	expected := jwt.Expected{
		Issuer: expectedIssuer,
	}
	if expectedAudience != "" {
		expected.AnyAudience = jwt.Audience{expectedAudience}
	}

	if err := claims.Claims.ValidateWithLeeway(expected, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return &claims, nil
}

// stripIdentityHeaders removes all client-supplied identity headers.
// The gateway is the sole authority for setting these after JWT validation.
// Prevents header injection on every path.
//
// Canonical identity headers (emitted post-JWT): X-User-Id, X-Org-Id, X-Roles.
// Auxiliary headers emitted by the gateway: X-User-Email, X-Phone-Number,
// X-User-IsAdmin. Everything else is legacy and MUST be stripped unconditionally.
func stripIdentityHeaders(r *http.Request) {
	// Canonical identity headers — stripped before re-injection so a
	// client-supplied value can never survive the middleware.
	r.Header.Del("X-User-Id")
	r.Header.Del("X-Org-Id")
	r.Header.Del("X-Roles")
	// Gateway-emitted auxiliaries.
	r.Header.Del("X-User-Email")
	r.Header.Del("X-Phone-Number")
	r.Header.Del("X-User-IsAdmin")
	// Non-canonical legacy identity headers — clients may not use these.
	r.Header.Del("X-User-Role")  // singular legacy
	r.Header.Del("X-User-Roles") // plural legacy (renamed to X-Roles)
	r.Header.Del("X-User-Name")
	r.Header.Del("X-Tenant-Id")
	r.Header.Del("X-Tenant-ID")
	r.Header.Del("X-Org") // bare legacy
	// Strip every legacy vendor-prefixed header (X-IAM-*, X-HANZO-*).
	for key := range r.Header {
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "X-IAM-") || strings.HasPrefix(upper, "X-HANZO-") {
			r.Header.Del(key)
		}
	}
}

// isAPIKey returns true for opaque API keys that should bypass JWT validation.
// These are validated by the backend services (cloud-api via IAM).
//
// Recognized prefixes:
//   - hk-  Hanzo IAM API keys
//   - sk-  Provider keys (OpenAI, Anthropic, etc.)
//   - fw_  Fireworks keys
//   - hz_  Hanzo widget keys (validated by cloud-api)
//   - pk-  Publishable/read-only keys
func isAPIKey(token string) bool {
	return strings.HasPrefix(token, "hk-") ||
		strings.HasPrefix(token, "sk-") ||
		strings.HasPrefix(token, "fw_") ||
		strings.HasPrefix(token, "hz_") ||
		strings.HasPrefix(token, "pk-")
}

// extractBearerToken extracts a Bearer token from Authorization or X-Authorization headers.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		auth = r.Header.Get("X-Authorization")
	}
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

// extractTokenFromCookie extracts the access token from common cookie names.
func extractTokenFromCookie(r *http.Request) string {
	// Try common cookie names used by Casdoor
	cookieNames := []string{
		"casdoor_access_token",
		"access_token",
		"hanzo_token",
	}

	for _, name := range cookieNames {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}

	return ""
}
