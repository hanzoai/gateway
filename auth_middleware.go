package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
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
	// Permissions claim — three accepted shapes:
	//   1. Pre-computed numeric bit-field: `42` (passed through verbatim)
	//   2. Plain []string of permission/role names: `["admin", "live"]`
	//   3. Casdoor []*Permission objects: `[{"name":"admin"}, {"name":"live"}]`
	// Whichever shape arrives, the gateway converts it to a base-10 int
	// matching commerce's util/permission/permission.go bit positions.
	Permissions json.RawMessage `json:"permissions"`
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

// permissionBits is the canonical name → bit-position map. Values MUST
// match commerce/util/permission/permission.go exactly; the iota order
// there is the single source of truth. Only stable, well-known names
// are translated — every other token (e.g. ad-hoc authz policy names)
// maps to zero. Lookups are case-insensitive.
//
// To extend: add a constant in commerce, then add the matching entry
// here. Forwards-only — never re-number existing entries or downstream
// services break.
var permissionBits = map[string]int64{
	"live":             1 << 2,  // 4
	"test":             1 << 3,  // 8
	"admin":            1 << 4,  // 16
	"published":        1 << 5,  // 32
	"secret":           1 << 6,  // 64
	"authorize":        1 << 7,  // 128
	"capture":          1 << 8,  // 256
	"bundle":           1 << 9,
	"campaign":         1 << 10,
	"collection":       1 << 11,
	"coupon":           1 << 12,
	"form":             1 << 13,
	"order":            1 << 14,
	"organization":     1 << 15,
	"payment":          1 << 16,
	"plan":             1 << 17,
	"product":          1 << 18,
	"referral":         1 << 19,
	"referrer":         1 << 20,
	"store":            1 << 21,
	"subscriber":       1 << 22,
	"user":             1 << 23,
	"variant":          1 << 24,
	"readbundle":       1 << 25,
	"readcampaign":     1 << 26,
	"readcollection":   1 << 27,
	"readcoupon":       1 << 28,
	"readform":         1 << 29,
	"readorder":        1 << 30,
	"readorganization": 1 << 31,
	"readpayment":      1 << 32,
	"readplan":         1 << 33,
	"readproduct":      1 << 34,
	"readreferral":     1 << 35,
	"readreferrer":     1 << 36,
	"readstore":        1 << 37,
	"readsubscriber":   1 << 38,
	"readuser":         1 << 39,
	"readvariant":      1 << 40,
	"writebundle":      1 << 41,
	"writecampaign":    1 << 42,
	"writecollection":  1 << 43,
	"writecoupon":      1 << 44,
	"writeform":        1 << 45,
	"writeorder":       1 << 46,
	"writeorganization": 1 << 47,
	"writepayment":     1 << 48,
	"writeplan":        1 << 49,
	"writeproduct":     1 << 50,
	"writereferral":    1 << 51,
	"writereferrer":    1 << 52,
	"writestore":       1 << 53,
	"writesubscriber":  1 << 54,
	"writeuser":        1 << 55,
	"writevariant":     1 << 56,
	"return":           1 << 57,
	"readreturn":       1 << 58,
	"writereturn":      1 << 59,
}

// computePermissionsBitField turns the raw "permissions" claim into the
// base-10 int64 carried by X-User-Permissions. Accepted shapes:
//   - JSON number (already a bit-field)
//   - []string of permission names
//   - []{"name": "..."} Casdoor permission objects
// The optional `extra` argument lets the caller OR-in additional bits
// derived from other claims (e.g. isAdmin → Admin|Live). Unknown names
// are dropped rather than failing the request — gateway is forwards-
// compatible with new IAM permissions, but never grants more than the
// JWT explicitly carries.
//
// Returns (bits, true) when bits > 0 — caller sets the header. Returns
// (0, false) when nothing maps — caller OMITS the header. Commerce treats
// absent and "0" identically (bit.Field(0)), but the gateway emits the
// minimal canonical form: present iff non-zero.
func computePermissionsBitField(raw json.RawMessage, extra int64) (int64, bool) {
	bits := extra
	if len(raw) == 0 {
		return bits, bits != 0
	}

	// Shape 1: bare numeric bit-field. JSON unmarshals into int64 cleanly.
	var asNumber int64
	if err := json.Unmarshal(raw, &asNumber); err == nil {
		if asNumber > 0 {
			bits |= asNumber
		}
		return bits, bits != 0
	}

	// Shape 2: []string of permission/role names.
	var asStrings []string
	if err := json.Unmarshal(raw, &asStrings); err == nil {
		for _, n := range asStrings {
			if b, ok := permissionBits[strings.ToLower(strings.TrimSpace(n))]; ok {
				bits |= b
			}
		}
		return bits, bits != 0
	}

	// Shape 3: []map[string]any — Casdoor's []*Permission objects.
	var asObjects []map[string]any
	if err := json.Unmarshal(raw, &asObjects); err == nil {
		for _, o := range asObjects {
			if n, ok := o["name"].(string); ok {
				if b, found := permissionBits[strings.ToLower(strings.TrimSpace(n))]; found {
					bits |= b
				}
			}
		}
		return bits, bits != 0
	}

	// Unparseable claim — fail closed: do not propagate any bits.
	return extra, extra != 0
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
// Canonical identity headers (the only ones downstream services should rely on):
//   - X-User-Id:           user ID from JWT "sub" (fallback: preferred_username, name)
//   - X-Org-Id:            org slug from JWT "owner" claim
//   - X-Roles:             comma-joined role names from JWT "roles" claim
//   - X-User-Permissions:  base-10 int64 bit-field derived from JWT permissions
//                          + isAdmin (commerce treats absent/0 as no rights).
//
// Auxiliary headers (derivatives of the JWT for convenience):
//   - X-User-Email:   email from JWT "email" claim
//   - X-Phone-Number: phone from JWT "phone_number" or "phone" claim
//   - X-User-IsAdmin: "true" if the JWT asserts isAdmin
//
// Trust boundary: all of the above are stripped on ingress (see
// stripIdentityHeaders) and only re-set after the JWT is validated. A
// client-supplied X-User-Permissions can NEVER reach a downstream
// service — Red P0-1 (2026-04-27).
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

		// Inject the canonical identity headers for downstream services.
		// X-User-Id <- sub, X-Org-Id <- owner, X-Roles <- roles (comma-joined),
		// X-User-Permissions <- bit.Field derived from JWT permissions claim
		// + isAdmin. Auxiliary headers (email, phone, isAdmin) are strictly
		// derivative of the JWT and may be consumed by services that need them.
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

		// Mint X-User-Permissions from the validated JWT. isAdmin implies
		// the Admin|Live bits (commerce's permission.Admin|permission.Live);
		// the explicit "permissions" claim is OR'd on top. Absent claim +
		// non-admin user → header is omitted, which commerce parses as
		// bit.Field(0) — fail-closed by design (commerce CLAUDE.md).
		var extraBits int64
		if claims.IsAdmin {
			extraBits = permissionBits["admin"] | permissionBits["live"]
		}
		if bits, set := computePermissionsBitField(claims.Permissions, extraBits); set {
			c.Request.Header.Set("X-User-Permissions", strconv.FormatInt(bits, 10))
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
// Canonical identity headers (emitted post-JWT): X-User-Id, X-Org-Id, X-Roles,
// X-User-Permissions. Auxiliary headers emitted by the gateway: X-User-Email,
// X-Phone-Number, X-User-IsAdmin. Everything else is legacy and MUST be
// stripped unconditionally. New mint-targets MUST be added here first — the
// strip-list is the trust boundary.
func stripIdentityHeaders(r *http.Request) {
	// Canonical identity headers — stripped before re-injection so a
	// client-supplied value can never survive the middleware.
	r.Header.Del("X-User-Id")
	r.Header.Del("X-Org-Id")
	r.Header.Del("X-Roles")
	r.Header.Del("X-User-Permissions") // bit.Field; commerce treats absent as 0
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

// gatewayMintedIdentityHeaders is the authoritative list of identity
// headers the gateway is allowed to emit downstream. Every entry here
// MUST also appear in stripIdentityHeaders so a client cannot forge a
// header the gateway later mints over (or forge one the gateway does
// NOT mint, which would still be untrusted-but-present downstream).
// The contract test in auth_middleware_security_test.go enforces this.
var gatewayMintedIdentityHeaders = []string{
	"X-User-Id",
	"X-Org-Id",
	"X-Roles",
	"X-User-Permissions",
	"X-User-Email",
	"X-Phone-Number",
	"X-User-IsAdmin",
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
	cookieNames := []string{
		"iam_access_token",
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
