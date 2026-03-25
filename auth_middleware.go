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
	// Email
	Email string `json:"email"`
	// User type
	Type string `json:"type"`
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
			"/__health",
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
// Header injection:
//   - X-IAM-Org-Id:     org slug from JWT "owner" claim
//   - X-IAM-User-Id:    user ID from JWT "sub" claim
//   - X-IAM-User-Email: email from JWT "email" claim
//
// Billing:
//   - Checks commerce service for positive balance
//   - Fail-open: if billing service is unreachable, request proceeds
//   - If balance <= 0: returns 402 Payment Required
//
// Public endpoints (configurable allowlist) bypass all auth checks.
func NewAuthMiddleware(cfg AuthConfig) gin.HandlerFunc {
	// When auth is disabled (AUTH_ENABLED=false), pass all requests through
	// without any token validation or billing checks.
	if !cfg.Enabled {
		return func(c *gin.Context) {
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
		claims, err := validateToken(token, cache, cfg.Issuer)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": fmt.Sprintf("Invalid token: %s", err.Error()),
			})
			return
		}

		orgID := claims.Owner
		userID := claims.Subject
		userEmail := claims.Email

		// Inject IAM identity headers for downstream services.
		// Generic X-IAM-* prefix — not vendor-specific, works across all orgs.
		c.Request.Header.Set("X-IAM-Org-Id", orgID)
		c.Request.Header.Set("X-IAM-User-Id", userID)
		c.Request.Header.Set("X-IAM-User-Email", userEmail)

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
					"message": "Your account has insufficient balance. Please add funds at https://billing.hanzo.ai",
					"user":    billingUser,
				})
				return
			}
		}

		c.Next()
	}
}

// validateToken parses and validates a JWT token using the cached JWKS.
func validateToken(rawToken string, cache *jwksCache, expectedIssuer string) (*hanzoJWTClaims, error) {
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
	// Validate standard claims
	expected := jwt.Expected{
		Issuer: expectedIssuer,
	}

	// Only validate issuer if it's set in the token
	if claims.Issuer != "" && expectedIssuer != "" {
		if err := claims.Claims.ValidateWithLeeway(expected, 2*time.Minute); err != nil {
			return nil, fmt.Errorf("token validation failed: %w", err)
		}
	}

	// Check expiry
	if claims.Expiry != nil && claims.Expiry.Time().Before(time.Now().Add(-2*time.Minute)) {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
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

// extractBearerToken extracts a Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
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
