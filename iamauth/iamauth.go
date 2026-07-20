// Package iamauth is the single source of truth for Hanzo IAM JWT
// validation at the edge. It is deliberately dependency-light — only
// go-jose + net/http — so both the heavyweight gin/KrakenD gateway
// middleware (package gateway) and the lightweight host-routing ingress
// (cmd/ingress) validate tokens through exactly one implementation.
//
// What lives here: JWKS fetch/cache, JWT validation (issuer + audience +
// expiry always enforced), token extraction (Bearer, HTTP Basic where the
// password is the token — the idiomatic `go`/.netrc proxy auth path — and
// cookie), the identity-header strip trust boundary, and minimal identity
// injection. Billing, permission bit-fields, and gin glue stay in package
// gateway; those are commerce-coupled and not part of the edge contract.
package iamauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
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
)

// Membership is one org the subject may act in, plus its coarse role there. It is
// the unit of the `orgs` membership SET IAM emits so the edge can authorize an
// org-switch statelessly (X-Org-Id ∈ orgs) with no round-trip.
type Membership struct {
	Org  string `json:"org"`            // the org slug the subject may act in
	Role string `json:"role,omitempty"` // coarse org role: owner | admin | member
}

// Claims are the JWT claims emitted by Hanzo IAM (hanzo.id). The gateway
// aliases its hanzoJWTClaims to this type, so the shape is shared.
type Claims struct {
	jwt.Claims

	Owner             string          `json:"owner"`              // HOME org slug (identity + billing anchor)
	Orgs              []Membership    `json:"orgs"`               // membership set: every org the subject may act in (home + teams)
	Project           string          `json:"project"`            // project scope within the org (optional; empty ⟹ default project)
	BillingAccount    string          `json:"billing_account"`    // funding account id (optional attribution hint; empty ⟹ cloud resolves the debit account)
	Name              string          `json:"name"`               // display name
	PreferredUsername string          `json:"preferred_username"` // fallback id
	Email             string          `json:"email"`
	Phone             string          `json:"phone"`        // IAM E.164
	PhoneNumber       string          `json:"phone_number"` // OIDC standard
	Type              string          `json:"type"`
	IsAdmin           bool            `json:"isAdmin"` // ORG-level admin (an org owner) — NEVER the money/superadmin bit
	Roles             json.RawMessage `json:"roles"`
	Permissions       json.RawMessage `json:"permissions"`
}

// EffectiveOrg resolves the org a request acts in — the value the edge mints into
// X-Org-Id — given the org the client REQUESTED (X-Act-As-Org, empty when none).
// It is the ONE org-switch predicate: the requested org is honored iff the subject
// is a member of it (the HOME org `owner` is always an implicit member); anything
// else falls back to the home org. So a caller can only ever act in — and spend
// from — an org IAM granted, and can never switch beyond its membership set. The
// bool reports whether an explicit, non-home request was HONORED (false when it
// was absent, was already home, or was refused for non-membership).
func (c *Claims) EffectiveOrg(requested string) (string, bool) {
	home := strings.TrimSpace(c.Owner)
	requested = strings.TrimSpace(requested)
	if requested == "" || strings.EqualFold(requested, home) {
		return home, false
	}
	for _, m := range c.Orgs {
		if org := strings.TrimSpace(m.Org); strings.EqualFold(org, requested) {
			return org, true // the CANONICAL membership slug, never the client's casing
		}
	}
	return home, false // requested outside the membership set → fail closed to home
}

// AdminOrg is the reserved org slug Hanzo IAM seeds PLATFORM (sudo) admins into.
// Platform sudo is ONE predicate — membership in this org — with NO redundant
// boolean flag. Commerce/cloud/iam gate on the SAME org == AdminOrg, so the
// platform-sudo predicate means byte-for-byte the same thing on both sides of the
// trust boundary (gateway mints X-Org-Id from `owner`; subsystems enforce org=="admin").
const AdminOrg = "admin"

// PlatformSudo reports whether these claims belong to a Hanzo PLATFORM (sudo)
// admin — the ONLY principal that may mint free balance, charge cards, or act
// cross-org. The signal is the home org: owner == AdminOrg. There is NO separate
// IsGlobalAdmin/IsSuperAdmin boolean — the org IS the capability (the redundant
// flag is dropped, per the canonical SuperAdmin ⟺ owner=="admin" model).
//
// Plain IsAdmin is deliberately NOT trusted: it is an ORG-level role (an org owner
// carries IsAdmin=true within their own org). Gating the money/admin permission bit
// on it let any org owner satisfy commerce's TokenRequired(permission.Admin) money
// gates → unlimited free balance.
func (c *Claims) PlatformSudo() bool {
	if c == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(c.Owner), AdminOrg)
}

// UserID resolves the canonical user identifier: sub, then
// preferred_username, then name. IAM may leave sub empty.
func (c *Claims) UserID() string {
	if c.Subject != "" {
		return c.Subject
	}
	if c.PreferredUsername != "" {
		return c.PreferredUsername
	}
	return c.Name
}

// DefaultProject is the reserved id of every org's default project. It is the
// wire-contract value shared with cloud (clients/principal.DefaultProject): an
// absent project claim and the literal "default" denote the SAME scope. The edge
// therefore omits X-Project-Id for it (minimal-canonical form — absent header ⟺
// default project), so downstream keying keeps today's un-suffixed keys.
const DefaultProject = "default"

// MintedProject returns the project id to stamp into X-Project-Id, or "" when the
// edge must OMIT the header. The project rides in the validated JWT `project`
// claim, scoped to the caller's org exactly like `owner` — trusted, not forgeable.
// The default project (absent claim, or the literal "default") mints nothing,
// mirroring how X-User-IsAdmin / X-User-Email are omitted at their zero value;
// downstream then resolves the default and preserves single-project behavior.
func (c *Claims) MintedProject() string {
	p := strings.TrimSpace(c.Project)
	if p == "" || p == DefaultProject {
		return ""
	}
	return p
}

// MintedBillingAccount returns the funding account id to stamp into
// X-Billing-Account-Id, or "" when the edge must OMIT the header. The account
// rides in the validated JWT `billing_account` claim, scoped to the caller's org
// exactly like `project` — trusted, not forgeable. Unlike the project claim there
// is NO reserved default: an absent/empty account simply mints nothing (it is an
// attribution hint; cloud + commerce resolve the real debit account server-side).
func (c *Claims) MintedBillingAccount() string {
	return strings.TrimSpace(c.BillingAccount)
}

// Config is the edge validation configuration.
type Config struct {
	JWKSURL string
	Issuer  string
	// Audiences is the allowlist of acceptable `aud` values. A token passes
	// when its audience matches ANY entry (OR semantics). IAM (Casdoor)
	// stamps user tokens with aud=<client_id> (e.g. hanzo-app), never the
	// gateway origin, so a single fixed audience rejects every normal user
	// JWT — the allowlist is the fix. An empty list disables the audience
	// check; AudiencesFromEnv never returns empty, so it is always enforced.
	Audiences []string
	JWKSTTL   time.Duration
}

// DefaultAudiences is the baked allowlist of acceptable JWT audiences: the
// known Hanzo IAM client_ids (each app's `aud` is its client_id) plus the
// gateway origin. It is the single source of truth shared by the ingress and
// the gin/KrakenD middleware. Forwards-only: append new client_ids, never
// remove. Override entirely with GATEWAY_ALLOWED_AUDIENCES (comma-separated).
var DefaultAudiences = []string{
	"hanzo-app",
	"hanzo-console",
	"hanzo-chat",
	"hanzo-id",
	"hanzo-admin-guard",
	"admin-console",
	"hanzo-world",
	"cowork",
	"https://api.hanzo.ai",
}

// AudiencesFromEnv resolves the audience allowlist. GATEWAY_ALLOWED_AUDIENCES
// (comma-separated), when set, fully replaces the baked default. Otherwise the
// baked DefaultAudiences is used; the legacy single-value AUTH_AUDIENCE, when
// set, is folded IN (it widens, never narrows — so a live env still pinned to
// AUTH_AUDIENCE=https://api.hanzo.ai keeps that value in an already-inclusive
// set rather than collapsing the allowlist to one entry). The result is never
// empty, so the audience check is always enforced.
func AudiencesFromEnv() []string {
	if v := os.Getenv("GATEWAY_ALLOWED_AUDIENCES"); v != "" {
		if list := splitAndTrim(v); len(list) > 0 {
			return list
		}
	}
	out := append([]string(nil), DefaultAudiences...)
	if legacy := strings.TrimSpace(os.Getenv("AUTH_AUDIENCE")); legacy != "" {
		out = appendUnique(out, legacy)
	}
	return out
}

// splitAndTrim splits a comma-separated list and drops empty entries.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// appendUnique appends v to list unless already present.
func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// ConfigFromEnv reads the same AUTH_* variables the gateway uses, with the
// same defaults, so the gateway and ingress agree on the IAM authority.
func ConfigFromEnv() Config {
	return Config{
		JWKSURL:   envOr("AUTH_JWKS_URL", "https://hanzo.id/.well-known/jwks"),
		Issuer:    envOr("AUTH_ISSUER", "https://hanzo.id"),
		Audiences: AudiencesFromEnv(),
		JWKSTTL:   15 * time.Minute,
	}
}

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

// ----------------------------------------------------------------------------
// JWKS cache
// ----------------------------------------------------------------------------

// JWKSCache caches JWKS keys with TTL-based refresh and stale-on-error.
type JWKSCache struct {
	mu        sync.RWMutex
	keys      *gojose.JSONWebKeySet
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

// NewJWKSCache returns a cache for the given JWKS URL and TTL.
func NewJWKSCache(url string, ttl time.Duration) *JWKSCache {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &JWKSCache{
		url:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Keys returns the cached key set, refreshing past TTL. On fetch error with
// a previously-cached set, the stale set is returned rather than failing.
func (c *JWKSCache) Keys() (*gojose.JSONWebKeySet, error) {
	c.mu.RLock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		keys := c.keys
		c.mu.RUnlock()
		return keys, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil && time.Since(c.fetchedAt) < c.ttl {
		return c.keys, nil
	}

	keys, err := c.fetch()
	if err != nil {
		if c.keys != nil {
			return c.keys, nil
		}
		return nil, err
	}
	c.keys = keys
	c.fetchedAt = time.Now()
	return keys, nil
}

func (c *JWKSCache) fetch() (*gojose.JSONWebKeySet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("jwks: create request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}
	var jwks gojose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	return &jwks, nil
}

// ----------------------------------------------------------------------------
// Validation
// ----------------------------------------------------------------------------

// ValidateToken parses and validates a JWT against the cached JWKS. Issuer,
// audience (when an allowlist is configured), and expiry are ALWAYS enforced;
// a token missing the issuer claim is rejected. The token passes the audience
// check when its `aud` matches ANY entry in expectedAudiences (OR semantics).
// An empty allowlist disables the audience check — callers that want it
// enforced (all production callers) pass a non-empty list.
func ValidateToken(rawToken string, cache *JWKSCache, expectedIssuer string, expectedAudiences []string) (*Claims, error) {
	tok, err := jwt.ParseSigned(rawToken, []gojose.SignatureAlgorithm{
		gojose.RS256, gojose.RS384, gojose.RS512,
		gojose.ES256, gojose.ES384, gojose.ES512,
		gojose.PS256, gojose.PS384, gojose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	keys, err := cache.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	var claims Claims
	var lastErr error

	for _, header := range tok.Headers {
		if header.KeyID != "" {
			for _, key := range keys.Key(header.KeyID) {
				if err := tok.Claims(key.Key, &claims); err == nil {
					goto validated
				} else {
					lastErr = err
				}
			}
		}
	}
	for _, key := range keys.Keys {
		if key.Use == "sig" || key.Use == "" {
			if _, ok := key.Key.(*rsa.PublicKey); ok {
				if err := tok.Claims(key.Key, &claims); err == nil {
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
	// Reject a missing issuer — an empty Expected.Issuer would skip the
	// comparison and let tokens from any issuer pass.
	if claims.Claims.Issuer == "" {
		return nil, fmt.Errorf("invalid token: missing issuer")
	}
	expected := jwt.Expected{Issuer: expectedIssuer}
	if len(expectedAudiences) > 0 {
		expected.AnyAudience = jwt.Audience(expectedAudiences)
	}
	if err := claims.Claims.ValidateWithLeeway(expected, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	return &claims, nil
}

// Validator binds a Config to a JWKS cache for repeated edge validation.
type Validator struct {
	cfg   Config
	cache *JWKSCache
}

// NewValidator builds a Validator from cfg.
func NewValidator(cfg Config) *Validator {
	return &Validator{cfg: cfg, cache: NewJWKSCache(cfg.JWKSURL, cfg.JWKSTTL)}
}

// Validate extracts a token from the request (Bearer / Basic / cookie) and
// validates it. Returns the empty-token sentinel ErrNoToken when absent so
// callers can distinguish "missing" from "invalid".
func (v *Validator) Validate(r *http.Request) (*Claims, error) {
	tok := ExtractToken(r)
	if tok == "" {
		return nil, ErrNoToken
	}
	return ValidateToken(tok, v.cache, v.cfg.Issuer, v.cfg.Audiences)
}

// ValidateRaw validates a raw token string (no *http.Request) through the
// validator's bound config + JWKS cache. Used by callers that already hold a
// token out-of-band — e.g. an OAuth2 code-exchange handler validating the
// id_token / access_token it just received.
func (v *Validator) ValidateRaw(rawToken string) (*Claims, error) {
	if rawToken == "" {
		return nil, ErrNoToken
	}
	return ValidateToken(rawToken, v.cache, v.cfg.Issuer, v.cfg.Audiences)
}

// ErrNoToken indicates no credential was present on the request.
var ErrNoToken = fmt.Errorf("no token")

// ----------------------------------------------------------------------------
// Token extraction
// ----------------------------------------------------------------------------

// ExtractToken pulls a token from, in order: Authorization/X-Authorization
// Bearer, HTTP Basic (the password — which is how `go`'s module fetcher and
// curl send a .netrc credential to a proxy), then a session cookie.
func ExtractToken(r *http.Request) string {
	if t := BearerToken(r); t != "" {
		return t
	}
	if t := BasicToken(r); t != "" {
		return t
	}
	return CookieToken(r)
}

// BearerToken extracts a Bearer token from Authorization or X-Authorization.
func BearerToken(r *http.Request) string {
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

// BasicToken extracts the token from an HTTP Basic Authorization header. The
// token is taken from the password field (username ignored), falling back to
// the username when the password is empty. This is the canonical way a `go`
// client authenticates to a module proxy via ~/.netrc:
//
//	machine goproxy.hanzo.ai login <email> password <IAM token>
func BasicToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return ""
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return ""
	}
	if pass != "" {
		return pass
	}
	return user
}

// CookieToken extracts an access token from common session cookie names.
func CookieToken(r *http.Request) string {
	for _, name := range []string{"iam_access_token", "access_token", "hanzo_token"} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// IsAPIKey reports whether the token is an opaque backend-validated API key
// (validated downstream, not as a JWT here).
func IsAPIKey(token string) bool {
	return strings.HasPrefix(token, "hk-") ||
		strings.HasPrefix(token, "sk-") ||
		strings.HasPrefix(token, "fw_") ||
		strings.HasPrefix(token, "hz_") ||
		strings.HasPrefix(token, "pk-")
}

// ----------------------------------------------------------------------------
// Identity headers — the trust boundary
// ----------------------------------------------------------------------------

// MintedIdentityHeaders is the authoritative set the edge may emit. Every
// entry MUST be stripped on ingress (StripIdentityHeaders) so a client can
// never forge one the edge later mints over.
var MintedIdentityHeaders = []string{
	"X-User-Id",
	"X-Org-Id",
	"X-User-Owner",
	"X-Project-Id",
	"X-Billing-Account-Id",
	"X-Roles",
	"X-User-Permissions",
	"X-User-Email",
	"X-Phone-Number",
	"X-User-IsAdmin",
	// No platform-admin boolean is minted anymore (platform sudo = org == AdminOrg).
	// The legacy X-User-IsGlobalAdmin stays in the STRIP set below, not here.
}

// StripIdentityHeaderNames is the AUTHORITATIVE, COMPLETE set of identity headers
// the edge mints (or a backend consumes) and therefore MUST strip on ingress so a
// forged value can never survive. Every name is BRAND-NEUTRAL and EXACT — there
// are deliberately NO X-VENDOR-* wildcard families (no X-IAM-*, no X-HANZO-*): the
// shared edge also fronts Lux/Zoo-branded deployments, so a hardcoded vendor
// prefix is wrong there, AND an exact-name-only set is the whole set an ingress
// `headers` middleware can strip (Traefik cannot wildcard). Single source of truth:
// StripIdentityHeaders iterates it, and the ingress `waitlist-strip` is generated
// from it (`waitlist-guard -print-strip-middleware`) so the two cannot drift — with
// no wildcard family, the generated strip now covers the FULL set with no gap.
// Forwards-only: append, never remove.
//
//   - X-User-IsGlobalAdmin: LEGACY platform-admin header — NO LONGER MINTED (platform
//     sudo is now org == AdminOrg, no boolean). Kept in the strip set as defense so a
//     client can never forge one a not-yet-migrated reader might still trust.
//   - X-Org-Id: the per-org billing/tenant selector (commerce, cloud metering) —
//     re-minted from the validated JWT only; a raw client value is cross-org IDOR.
//   - X-Project-Id: org SUB-SCOPE, minted from a validated claim; a raw client
//     value is a cross-project IDOR.
//   - X-Billing-Account-Id: funding-account attribution hint, minted from a
//     validated claim; a raw client value is a cross-account billing forgery.
//
// The legacy vendor-prefixed identity headers (X-IAM-Org-Id, X-Hanzo-Org, …) have
// been RENAMED to these neutral names at every setter + consumer, so no identity
// header uses a vendor prefix anymore — which is exactly what lets the ingress
// (Traefik, exact-name only) strip the FULL identity set with no wildcard gap.
var StripIdentityHeaderNames = []string{
	"X-User-Id",
	"X-Org-Id",
	"X-User-Owner",
	"X-Roles",
	"X-User-Permissions",
	"X-User-Email",
	"X-Phone-Number",
	"X-User-IsAdmin",
	"X-User-IsGlobalAdmin",
	"X-Project-Id",
	"X-Billing-Account-Id",
	// Non-canonical legacy identity headers (still exact-name, still neutral).
	"X-User-Role",
	"X-User-Roles",
	"X-User-Name",
	"X-Tenant-Id",
	"X-Tenant-ID",
	"X-Org",
}

// StripIdentityHeaderPrefixes is the gateway's Go-side DEFENSE-IN-DEPTH: it deletes
// ANY stray vendor-prefixed header at the API chokepoint. This is brand-NEUTRAL —
// it only ever DELETES vendor junk (never mints/requires it), so it is correct on
// every deployment the shared edge fronts (Hanzo, Lux, Zoo). Identity headers are
// all neutral now (see StripIdentityHeaderNames), so this no longer catches any
// IDENTITY header — it is a backstop against a forged vendor header a backend might
// someday read (TestAllAuthPaths_NoXIdentityPassthrough). It is a GATEWAY-only Go
// strip; the ingress waitlist-strip needs no wildcard because the identity set it
// generates from StripIdentityHeaderNames is already complete + exact.
var StripIdentityHeaderPrefixes = []string{"X-IAM-", "X-HANZO-"}

// StripIdentityHeaders removes every client-supplied identity header (exact neutral
// names) plus, defensively, any stray vendor-prefixed header. The edge is the sole
// authority for identity; this MUST run before any bypass path so a forged value
// can never survive.
func StripIdentityHeaders(r *http.Request) {
	for _, h := range StripIdentityHeaderNames {
		r.Header.Del(h)
	}
	for key := range r.Header {
		upper := strings.ToUpper(key)
		for _, p := range StripIdentityHeaderPrefixes {
			if strings.HasPrefix(upper, p) {
				r.Header.Del(key)
				break
			}
		}
	}
}

// ActAsOrgHeader is the request header a client sets to act in a specific org it
// is a member of (an org-switch). The edge validates it against the token's
// membership set (Claims.EffectiveOrg), mints X-Org-Id from the result, and drops
// it — so it is a request INTENT, never a trusted identity header, and can only
// ever select an org IAM already granted. Absent ⟹ the home org.
const ActAsOrgHeader = "X-Act-As-Org"

// InjectIdentity sets the core identity headers from validated claims. This
// is the minimal edge identity (id, org, email, isAdmin) — roles and the
// permission bit-field stay in the commerce-coupled gateway middleware.
// Call StripIdentityHeaders first.
func InjectIdentity(r *http.Request, c *Claims) {
	r.Header.Set("X-User-Id", c.UserID())
	// X-Org-Id = the EFFECTIVE org: the org the client asked to act in
	// (X-Act-As-Org) when it is in the membership set, else the home org. The
	// intent header is consumed here so it never reaches a backend.
	effective, _ := c.EffectiveOrg(r.Header.Get(ActAsOrgHeader))
	r.Header.Del(ActAsOrgHeader)
	r.Header.Set("X-Org-Id", effective)
	// X-User-Owner = the immutable HOME org (JWT owner), distinct from X-Org-Id (the
	// EFFECTIVE org). Platform-sudo + billing key on the home org; stripped on
	// ingress so it is never forgeable.
	r.Header.Set("X-User-Owner", c.Owner)
	// Mint the org SUB-SCOPE X-Project-Id from the validated `project` claim,
	// exactly like X-Org-Id from `owner`. Omitted for the default project so the
	// header is present iff a non-default project is in scope (StripIdentityHeaders
	// already dropped any forgeable client copy).
	if project := c.MintedProject(); project != "" {
		r.Header.Set("X-Project-Id", project)
	}
	// Mint X-Billing-Account-Id from the validated `billing_account` claim, an
	// attribution hint mirroring X-Project-Id. Absent/empty mints nothing (no
	// reserved default); cloud + commerce resolve the real debit account.
	if acct := c.MintedBillingAccount(); acct != "" {
		r.Header.Set("X-Billing-Account-Id", acct)
	}
	if c.Email != "" {
		r.Header.Set("X-User-Email", c.Email)
	}
	if c.IsAdmin {
		r.Header.Set("X-User-IsAdmin", "true")
	}
	// NO platform-admin boolean is minted. Platform sudo is org == AdminOrg
	// (carried by X-Org-Id from the validated `owner`); subsystems gate on that.
	// The legacy X-User-IsGlobalAdmin header is still stripped on ingress so a
	// client can never forge it — it is simply never emitted.
}
