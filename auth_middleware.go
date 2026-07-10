package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hanzoai/gateway/v2/iamauth"
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

	// Audiences is the allowlist of acceptable JWT `aud` values. A token
	// passes when its audience matches ANY entry. IAM stamps user tokens with
	// aud=<client_id>, so a single fixed audience rejects every user JWT; the
	// allowlist (iamauth.AudiencesFromEnv) is the fix. Override entirely with
	// GATEWAY_ALLOWED_AUDIENCES.
	Audiences []string

	// Billing check endpoint (default: http://commerce.hanzo.svc.cluster.local:8001)
	BillingURL string

	// BillingToken is the COMMERCE_SERVICE_TOKEN for authenticating with Commerce.
	BillingToken string

	// BillingEnabled controls whether billing checks are performed.
	// Default: true (checks enabled). Set to false to disable.
	BillingEnabled bool

	// BillingPaths scopes balance enforcement to request paths matching one
	// of these prefixes. This is the one knob that keeps billing OFF for the
	// AI/validated (per-token billed downstream) and public routes while
	// ON for the metered must-gate platform surface (cloud/tasks/insights/
	// o11y/mpc/evals/licensing/product/provisioning/…). The /v1/commerce
	// funding surface is hard-excluded in code (billingPathMatch) regardless
	// of this list. Empty list enforces on every non-funding, non-public
	// route. Set BILLING_PATHS to the must-gate prefixes. One scope.
	BillingPaths []string

	// Paths that bypass auth entirely (exact prefix match)
	PublicPaths []string

	// Hosts that bypass auth entirely (e.g. hanzo.id for login)
	PublicHosts []string

	// If true, requests without a token are rejected (402/401).
	// If false (default), requests without a token pass through without headers.
	RequireAuth bool
}

// hanzoJWTClaims and the JWKS cache, token validation, extraction, and the
// identity-header trust boundary now live in package iamauth (the single
// edge-auth implementation shared with cmd/ingress). Thin shims preserving
// the symbols this file and its tests use are in auth_compat.go.

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
	// Then []map[string]any (IAM Role objects)
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
	"live":              1 << 2, // 4
	"test":              1 << 3, // 8
	"admin":             1 << 4, // 16
	"published":         1 << 5, // 32
	"secret":            1 << 6, // 64
	"authorize":         1 << 7, // 128
	"capture":           1 << 8, // 256
	"bundle":            1 << 9,
	"campaign":          1 << 10,
	"collection":        1 << 11,
	"coupon":            1 << 12,
	"form":              1 << 13,
	"order":             1 << 14,
	"organization":      1 << 15,
	"payment":           1 << 16,
	"plan":              1 << 17,
	"product":           1 << 18,
	"referral":          1 << 19,
	"referrer":          1 << 20,
	"store":             1 << 21,
	"subscriber":        1 << 22,
	"user":              1 << 23,
	"variant":           1 << 24,
	"readbundle":        1 << 25,
	"readcampaign":      1 << 26,
	"readcollection":    1 << 27,
	"readcoupon":        1 << 28,
	"readform":          1 << 29,
	"readorder":         1 << 30,
	"readorganization":  1 << 31,
	"readpayment":       1 << 32,
	"readplan":          1 << 33,
	"readproduct":       1 << 34,
	"readreferral":      1 << 35,
	"readreferrer":      1 << 36,
	"readstore":         1 << 37,
	"readsubscriber":    1 << 38,
	"readuser":          1 << 39,
	"readvariant":       1 << 40,
	"writebundle":       1 << 41,
	"writecampaign":     1 << 42,
	"writecollection":   1 << 43,
	"writecoupon":       1 << 44,
	"writeform":         1 << 45,
	"writeorder":        1 << 46,
	"writeorganization": 1 << 47,
	"writepayment":      1 << 48,
	"writeplan":         1 << 49,
	"writeproduct":      1 << 50,
	"writereferral":     1 << 51,
	"writereferrer":     1 << 52,
	"writestore":        1 << 53,
	"writesubscriber":   1 << 54,
	"writeuser":         1 << 55,
	"writevariant":      1 << 56,
	"return":            1 << 57,
	"readreturn":        1 << 58,
	"writereturn":       1 << 59,
}

// computePermissionsBitField turns the raw "permissions" claim into the
// base-10 int64 carried by X-User-Permissions. Accepted shapes:
//   - JSON number (already a bit-field)
//   - []string of permission names
//   - []{"name": "..."} IAM permission objects
//
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

	// Shape 3: []map[string]any — IAM []*Permission objects.
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

// billingChecker checks user billing status against Commerce API.
//
// Commerce endpoints used:
//
//	GET /v1/billing/balance?user={user}&currency=usd
//	  -> { "user": "...", "currency": "usd", "balance": 5000, "holds": 0, "available": 5000 }
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

// checkBalance reports whether the user has positive available balance.
//
// Contract — the caller distinguishes three states:
//
//	(true,  nil) commerce confirmed available > 0   → allow.
//	(false, nil) commerce confirmed available <= 0  → deny 402 (out of funds).
//	(false, err) balance could not be determined    → deny 503 (fail-closed).
//
// FAIL-CLOSED is deliberate: this is a paid, no-free product, so we never
// serve AI to a user whose balance we cannot verify. The only allow-without-
// proof case is when no billing URL is configured at all (not enforced).
//
// The user identifier is the IAM "org/sub" (e.g. "hanzo/alice").
func (b *billingChecker) checkBalance(userID string) (bool, error) {
	if b.baseURL == "" {
		return true, nil // Billing not configured -> not enforced.
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Commerce mounts its API under /v1 (commerce mount.go: Router.Group("/v1")
	// -> billing.Route -> GET /balance), NOT /api/v1. A wrong prefix 404s and,
	// fail-closed, denies every request — keep this in lockstep with commerce.
	u := fmt.Sprintf("%s/v1/billing/balance?user=%s&currency=usd", b.baseURL, url.QueryEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}

	// Authenticate with the Commerce service token (admin-scoped S2S).
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return false, err // Commerce unreachable -> deny.
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("commerce billing status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false, err
	}

	var result billingResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Available > 0, nil
}

// commercePathPrefix is the funding surface — the routes a user adds funds
// through. It is NEVER balance-gated: a 402 here would lock a zero-balance
// user out of the only page that lets them pay. The exclusion lives in code,
// not operator discipline, so it cannot be misconfigured away by BILLING_PATHS.
const commercePathPrefix = "/v1/commerce"

// billingPathMatch reports whether path falls under balance enforcement.
// The funding surface (commercePathPrefix) is always excluded. An empty prefix
// list enforces on every non-funding path; a non-empty list scopes enforcement
// to those prefixes — the metered must-gate surface — so the AI/validated and
// public routes are never balance-gated.
func billingPathMatch(path string, prefixes []string) bool {
	// Funding surface is never balance-gated, even when BILLING_PATHS lists it.
	if path == commercePathPrefix || strings.HasPrefix(path, commercePathPrefix+"/") {
		return false
	}
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
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

	// Audience is validated against an allowlist (iamauth.AudiencesFromEnv):
	// the known Hanzo client_ids + the gateway origin, overridable via
	// GATEWAY_ALLOWED_AUDIENCES. IAM stamps user tokens with aud=<client_id>,
	// so the prior single fixed audience rejected every user JWT. Audience
	// validation is ALWAYS enforced (the allowlist is never empty).
	audiences := iamauth.AudiencesFromEnv()

	billingURL := os.Getenv("AUTH_BILLING_URL")
	if billingURL == "" {
		billingURL = "http://commerce.hanzo.svc.cluster.local:8001"
	}

	billingToken := os.Getenv("COMMERCE_SERVICE_TOKEN")

	// Billing enforcement is the single responsibility of cloud's
	// balance_gate, which resolves hk- API keys, applies per-model pricing,
	// and exempts service keys — none of which the edge gateway can see.
	// The gateway must NOT double-gate balance, so billing is OFF by default.
	// Opt in only for edge-only deployments that front no balance_gate, via
	// BILLING_ENABLED=true. One way; one enforcement point.
	billingEnabled := os.Getenv("BILLING_ENABLED") == "true"

	// BILLING_PATHS scopes balance enforcement to these path prefixes (CSV).
	// Set this to the must-gate surface so the AI/validated and public routes
	// are never balance-gated. Empty = legacy global enforcement.
	var billingPaths []string
	if bp := os.Getenv("BILLING_PATHS"); bp != "" {
		billingPaths = strings.Split(bp, ",")
		for i := range billingPaths {
			billingPaths[i] = strings.TrimSpace(billingPaths[i])
		}
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
		Audiences:      audiences,
		BillingURL:     billingURL,
		BillingToken:   billingToken,
		BillingEnabled: billingEnabled,
		BillingPaths:   billingPaths,
		PublicPaths:    publicPaths,
		PublicHosts:    publicHosts,
		RequireAuth:    requireAuth,
	}
}

// Validate reports a fatal misconfiguration: billing enabled without the
// Commerce endpoint and service token it depends on. Enforced so enabling
// billing can never silently fail open (empty URL → checkBalance allows) nor
// 503-storm the whole metered surface (empty token → Commerce 401). The one
// caller that can return an error — gateway.Mount — refuses to start in this
// state; NewAuthMiddleware additionally fails the balance gate closed.
func (c AuthConfig) Validate() error {
	if !c.BillingEnabled {
		return nil
	}
	if c.BillingURL == "" {
		return fmt.Errorf("auth: BILLING_ENABLED=true requires AUTH_BILLING_URL (Commerce endpoint)")
	}
	if c.BillingToken == "" {
		return fmt.Errorf("auth: BILLING_ENABLED=true requires COMMERCE_SERVICE_TOKEN (from KMS)")
	}
	return nil
}

// NewAuthMiddleware creates a gin middleware that validates IAM JWT tokens,
// checks billing status, and injects identity headers for downstream services.
//
// Canonical identity headers (the only ones downstream services should rely on):
//   - X-User-Id:           user ID from JWT "sub" (fallback: preferred_username, name)
//   - X-Org-Id:            org slug from JWT "owner" claim
//   - X-Roles:             comma-joined role names from JWT "roles" claim
//   - X-User-Permissions:  base-10 int64 bit-field derived from JWT permissions
//   - isAdmin (commerce treats absent/0 as no rights).
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
// isErrorIngestPath matches ONLY the Sentry error-ingest wire endpoints:
// POST /v1/o11y/api/<project>/envelope/ and POST /v1/o11y/api/<project>/store/.
// The <project> segment varies, so it is matched by method + prefix + suffix — never
// a bare prefix — so the o11y read APIs under /v1/o11y/api/vN/… stay JWT-gated.
// (The trailing slash is the Sentry protocol form; the slash-less variant is
// tolerated defensively.)
func isErrorIngestPath(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	if !strings.HasPrefix(path, "/v1/o11y/api/") {
		return false
	}
	return strings.HasSuffix(path, "/envelope/") || strings.HasSuffix(path, "/envelope") ||
		strings.HasSuffix(path, "/store/") || strings.HasSuffix(path, "/store")
}

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

	// Fail-secure: billing enabled but its Commerce dependency is not fully
	// configured. gateway.Mount refuses to start in this state (cfg.Validate);
	// this covers the standalone path, which has no error return — the balance
	// gate denies the metered surface (503) instead of failing open. The
	// funding surface stays reachable (billingPathMatch excludes /v1/commerce).
	billingMisconfigured := cfg.BillingEnabled && (cfg.BillingURL == "" || cfg.BillingToken == "")
	if billingMisconfigured {
		log.Printf("gateway auth: BILLING_ENABLED=true but AUTH_BILLING_URL or COMMERCE_SERVICE_TOKEN is empty; metered surface fails closed (503) until both are set from KMS")
	}

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

		// Sentry-SDK error ingest is authenticated by a DSN key at the o11y backend
		// (not a Hanzo JWT), so it bypasses gateway JWT auth — but ONLY the exact
		// ingest verbs: POST to /v1/o11y/api/<project>/envelope|store/. This is
		// deliberately NOT a broad /v1/o11y or /v1/o11y/api allowlist: those would
		// skip JWT validation on the o11y READ APIs and break the X-Org-Id injection
		// the reads rely on (fail-closed → reads break). Identity headers were
		// already stripped above, so the ingest caller cannot spoof a tenant; the
		// o11y handler resolves the org from the DSN itself.
		if isErrorIngestPath(c.Request.Method, path) {
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
		// backend services directly (cloud, commerce, etc.), not by
		// the gateway. Pass them through without JWT validation.
		if isAPIKey(token) {
			c.Next()
			return
		}

		// Parse and validate JWT
		claims, err := validateToken(token, cache, cfg.Issuer, cfg.Audiences)
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
		// IAM may leave "sub" empty — fall back to preferred_username then name
		if userID == "" {
			userID = claims.PreferredUsername
		}
		if userID == "" {
			userID = claims.Name
		}
		userEmail := claims.Email
		// Phone: prefer OIDC phone_number, fall back to IAM phone field
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
		// Mint the org SUB-SCOPE X-Project-Id from the validated `project` claim,
		// exactly like X-Org-Id from `owner`. Absent/default project mints nothing
		// (minimal-canonical form) — downstream resolves the default and keeps
		// today's single-project behavior. The client copy was already stripped
		// (stripIdentityHeaders), so this is never forgeable.
		if project := claims.MintedProject(); project != "" {
			c.Request.Header.Set("X-Project-Id", project)
		}
		// Mint X-Billing-Account-Id from the validated `billing_account` claim, an
		// attribution hint mirroring X-Project-Id. Absent/empty mints nothing; the
		// client copy was already stripped (stripIdentityHeaders), so it is never
		// forgeable. Cloud + commerce resolve the real debit account server-side.
		if acct := claims.MintedBillingAccount(); acct != "" {
			c.Request.Header.Set("X-Billing-Account-Id", acct)
		}
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
		// Mint the PLATFORM superadmin signal ONLY for a real global admin — the
		// spoof-proof header commerce's money/cross-org gates read. Stripped on
		// ingress (stripIdentityHeaders → iamauth.StripIdentityHeaders), minted here
		// only from the validated GlobalAdmin() claim, so it can't be forged.
		if claims.GlobalAdmin() {
			c.Request.Header.Set("X-User-IsGlobalAdmin", "true")
		}

		// Mint X-User-Permissions from the validated JWT.
		//
		// The Admin bit is the MONEY/admin authority: commerce gates every
		// credit-creating and card-charging billing endpoint on
		// TokenRequired(permission.Admin), and bit.Field.Has is intersection
		// semantics — so whoever carries Admin satisfies those gates. It is
		// therefore GLOBAL-admin-only. An org-level admin (claims.IsAdmin — an org
		// OWNER like maxpower carries it within their own org) must NOT mint free
		// balance or charge cards platform-wide; granting them Admin was a
		// free-money hole (live-proven as Dave/maxpower). Live (real-money, not
		// sandbox) mode is orthogonal to authority and stays on IsAdmin so a normal
		// org owner's own real Square top-up keeps working. The explicit
		// "permissions" claim is OR'd on top. Absent claim + non-admin → header
		// omitted → commerce parses bit.Field(0), fail-closed (commerce CLAUDE.md).
		var extraBits int64
		if claims.IsAdmin {
			extraBits |= permissionBits["live"]
		}
		if claims.GlobalAdmin() {
			extraBits |= permissionBits["admin"]
		}
		if bits, set := computePermissionsBitField(claims.Permissions, extraBits); set {
			c.Request.Header.Set("X-User-Permissions", strconv.FormatInt(bits, 10))
		}

		// Balance gate — path-scoped + fail-closed (see checkBalance).
		//
		// Scope: cfg.BillingPaths (the metered must-gate surface — cloud,
		// tasks, insights, o11y, mpc, evals, licensing, product,
		// provisioning, …). The /v1/commerce funding surface is hard-excluded
		// (billingPathMatch) so a zero-balance user can always reach it to add
		// funds. The AI routes bill per-token downstream and the
		// validated/public routes are never balance-gated, so they are NOT in
		// BillingPaths and skip this gate. Empty BillingPaths enforces on every
		// non-funding, non-public route.
		//
		// Key: the IAM "org/sub" composite — org from owner/X-Org-Id, sub from
		// the user. Commerce's /v1/billing/balance is user-scoped under an org
		// (the verified contract); per-org billing would require a commerce-
		// side balance-model change first, so the org is carried in the key
		// rather than used alone.
		if cfg.BillingEnabled && userID != "" && billingPathMatch(path, cfg.BillingPaths) {
			// Fail closed when billing is enabled but misconfigured (no URL or
			// token) — never serve metered product we cannot bill for.
			if billingMisconfigured {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error":   "billing_unavailable",
					"message": "Billing is temporarily unavailable. Please retry shortly.",
				})
				return
			}

			// Construct the Commerce user identifier: org/username
			billingUser := userID
			if orgID != "" && !strings.Contains(userID, "/") {
				billingUser = orgID + "/" + userID
			}

			hasBalance, balErr := billing.checkBalance(billingUser)
			switch {
			case hasBalance:
				// allowed
			case balErr != nil:
				// Could not verify balance. Deny (no free), but signal an
				// outage rather than wrongly telling a paying user they are
				// out of funds.
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error":   "billing_unavailable",
					"message": "Billing is temporarily unavailable. Please retry shortly.",
				})
				return
			default:
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

// validateToken, the JWKS cache, the identity-header trust boundary,
// isAPIKey, and the token extractors now live in package iamauth — the one
// edge-auth implementation shared with cmd/ingress. The thin shims that keep
// this file's symbols stable are in auth_compat.go.
