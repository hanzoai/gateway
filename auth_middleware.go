package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/gateway/v2/token"
)

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	// Enabled controls whether the auth middleware is active.
	// Default: true. Set to false via AUTH_ENABLED=false to disable
	// all auth checks (useful for integration tests and development).
	Enabled bool

	// JWKS URL to fetch signing keys (default: https://hanzo.id/v1/iam/.well-known/jwks)
	JWKSURL string

	// Expected JWT issuer (default: https://hanzo.id)
	Issuer string

	// Audiences is the allowlist of acceptable JWT `aud` values. A token
	// passes when its audience matches ANY entry. IAM stamps user tokens with
	// aud=<client_id>, so a single fixed audience rejects every user JWT; the
	// allowlist (token.AudiencesFromEnv) is the fix. Override entirely with
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
// identity-header trust boundary live in hanzoai/authz + hanzoai/authz/edge (the
// edge-auth implementation shared with the estate). Thin shims preserving
// the symbols this file and its tests use are in auth_compat.go.

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
		jwksURL = "https://hanzo.id/v1/iam/.well-known/jwks"
	}

	issuer := os.Getenv("AUTH_ISSUER")
	if issuer == "" {
		issuer = "https://hanzo.id"
	}

	// Audience is validated against an allowlist (token.AudiencesFromEnv):
	// the known Hanzo client_ids + the gateway origin, overridable via
	// GATEWAY_ALLOWED_AUDIENCES. IAM stamps user tokens with aud=<client_id>,
	// so the prior single fixed audience rejected every user JWT. Audience
	// validation is ALWAYS enforced (the allowlist is never empty).
	audiences := token.AudiencesFromEnv()

	billingURL := os.Getenv("AUTH_BILLING_URL")
	if billingURL == "" {
		billingURL = "http://commerce.hanzo.svc.cluster.local:8001"
	}

	billingToken := os.Getenv("COMMERCE_SERVICE_TOKEN")

	// Billing enforcement is the single responsibility of cloud's
	// balance_gate, which resolves sk- API keys, applies per-model pricing,
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
// ingestRoots are the two prefixes the DSN-authed error wire arrives on. It is
// ONE list because it answers ONE question, and it is the same pair cloud's own
// module.IngestWire names: /v1/event is the door a minted DSN spells, and
// /v1/o11y/api is the suffix a stock Sentry SDK appends to whatever DSN path it
// is given — a third party's shape, received rather than published.
//
// THE TWO SIDES MUST AGREE. The gateway lets this class through tokenless and
// cloud DSN-authenticates it; a path one admits and the other refuses is a beacon
// that dies at 401 with nothing on either side saying why. This used to be two
// functions of identical shape differing only by prefix, which is two places for
// that agreement to rot.
var ingestRoots = []string{"/v1/event/", "/v1/o11y/api/"}

// isIngestPath is the ROUTE-CLASS selector for the tokenless DSN ingest plane.
// POST-only and suffix-anchored on {envelope,store}, NEVER a bare prefix, so it
// can never match a read: every error-plane READ — issues, discover, projects,
// logs, traces, stats — routes to the authed class and stays JWT-gated. Cloud
// DSN-authenticates this class and resolves the org FROM the DSN, so the gateway
// writes no identity for it. This is the routing selector for class 1, not a
// bypass hole in a global gate.
func isIngestPath(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	under := false
	for _, root := range ingestRoots {
		if strings.HasPrefix(path, root) {
			under = true
			break
		}
	}
	if !under {
		return false
	}
	// The trailing slash is the wire's form; the slash-less variant is tolerated
	// defensively.
	return strings.HasSuffix(path, "/envelope/") || strings.HasSuffix(path, "/envelope") ||
		strings.HasSuffix(path, "/store/") || strings.HasSuffix(path, "/store")
}

// The ALLOW/DENY ladder itself — strip, route class, public allowlists, token
// extraction, JWT validation, the identity write, the balance gate — is
// [authGate.admit] in authpolicy.go, which knows about no framework. Its
// transports are a few lines each: native zip for the HIP-0106 unified binary
// (mount.go) and gin for the legacy Lura edge (legacy_transports.go).
//
// validateToken, the JWKS cache, the identity-header trust boundary,
// the API-key test, and the token extractors live in hanzoai/authz/edge — the one
// edge-auth implementation shared with the estate. The thin shims that keep
// this file's symbols stable are in auth_compat.go.
