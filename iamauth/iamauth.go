// Package iamauth is the single source of truth for Hanzo IAM JWT
// validation at the edge. It is deliberately dependency-light — only
// go-jose + net/http — so both the heavyweight gin/Lura gateway
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
	"unicode"

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
	BillingAccount    string          `json:"billing_account"`    // WHO PAYS: `<kind>:<subject>`, signed by IAM (empty ⟹ pre-claim token; Payer falls back)
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

// EffectiveOrg resolves the org a request ACTS IN — the value the edge mints into
// X-Org-Id — from the org the client SELECTED (the inbound X-Org-Id, "" when none).
// It is the ONE org-switch predicate at the edge, and it has TWO branches:
//
//   - MASQUERADE (a human platform operator): the selection is honored with no
//     membership test. That is what platform sudo means — see Masquerade.
//   - EVERYONE ELSE: the selection is honored iff the token's SIGNED `orgs`
//     membership set contains it. The home org is always an implicit member.
//
// A selection outside the set is DISCARDED, not refused: the request continues in
// the home org, byte-for-byte indistinguishable from "no selection". So a stale
// switcher choice left in a browser after a membership is revoked reads the
// caller's OWN data and bills the caller's OWN ledger — never the requested org's,
// and never a 403 the UI has no way to explain.
//
// The comparison is VERBATIM — no trim, no case fold — mirroring cloud's isMember
// (hanzoai/cloud auth_identity.go). "acme" and "ACME" are DISTINCT orgs in IAM, so
// a fold would let a member of one select the other; a trim would collapse "acme "
// onto "acme". Both sides of the trust boundary must answer identically, or the
// edge and the in-binary path disagree about which ledger pays.
//
// The bool reports whether an explicit, non-home selection was HONORED (false when
// it was absent, was already home, or was discarded for non-membership).
func (c *Claims) EffectiveOrg(selected string) (string, bool) {
	home := c.Owner
	if selected == "" || selected == home || OrgHasUnsafeRune(selected) {
		return home, false
	}
	if c.Masquerade() {
		return selected, true // platform sudo: any org, no membership test
	}
	for _, m := range c.Orgs {
		if m.Org == selected {
			return selected, true
		}
	}
	return home, false // outside the membership set → fail closed to home
}

// LedgerOrg resolves the org that PAYS for a request — the org whose balance the
// edge gate checks — from the same client selection EffectiveOrg reads. It is
// deliberately a SECOND function with TWO explicit branches, not a clever reuse of
// the first, because acting and paying are different questions:
//
//   - MASQUERADE: the HOME org pays. An operator inspecting a customer's org must
//     never spend the customer's money, so the ledger stays on the admin org while
//     EffectiveOrg (the data scope) moves to the customer.
//   - EVERYONE ELSE: the org they act in pays. That IS the product — a person
//     belongs to several orgs, picks one, and that org is the payer of record.
//
// It takes the raw selection, exactly like EffectiveOrg, so the two can never be
// mis-threaded by a caller passing one's output into the other.
// Mirrors cloud's principal.BillingOrg.
func (c *Claims) LedgerOrg(selected string) string {
	if c.Masquerade() {
		return c.Owner
	}
	org, _ := c.EffectiveOrg(selected)
	return org
}

// OrgHasUnsafeRune reports whether s carries any whitespace, control, or
// zero-width/format rune — the class that defeats the injectivity of the org→org
// map. Transport OWS-trimming (and any TrimSpace downstream) silently drops such
// runes at the edges, so two DISTINCT IAM org names ("acme" vs "acme ", or an
// NBSP/ZWSP variant) would collapse onto ONE org. A selection bearing one is
// REFUSED (fail secure) rather than folded. Case and visible punctuation are
// deliberately NOT unsafe — they survive transport, so they stay distinct.
// Mirrors cloud's OrgHasUnsafeRune so both sides of the boundary refuse the
// same set.
func OrgHasUnsafeRune(s string) bool {
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
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

// machineType is IAM's `type` for a client_credentials identity (IAM stamps
// Type:"application" on a machine token). It is the discriminator that keeps a
// machine from ever inheriting platform sudo's cross-org reach.
const machineType = "application"

// kmsMachineAud is the audience suffix a per-org PaaS-KMS sync identity carries:
// "<owner>-platform-kms". It is bound to the token's OWN owner claim, so matching
// it certifies "the KMS machine for its own org" and widens nothing.
const kmsMachineAud = "-platform-kms"

// Machine reports whether these claims belong to a MACHINE (client_credentials)
// identity rather than a person. The primary signal is IAM's `type` claim; the
// owner-bound KMS audience is UNIONed on as a defensive fallback for a token
// minted before that claim existed. Fail-closed toward "human": an unknown/empty
// type is NOT a machine, so a real operator carrying no `type` is never locked out.
// Mirrors cloud's isMachinePrincipal.
func (c *Claims) Machine() bool {
	if c == nil {
		return false
	}
	if c.Type == machineType {
		return true
	}
	if c.Owner == "" {
		return false
	}
	mach := c.Owner + kmsMachineAud
	for _, a := range c.Audience {
		if a == mach {
			return true
		}
	}
	return false
}

// Masquerade reports whether these claims may act in an org OUTSIDE the signed
// membership set — the platform operator's cross-org view. It is PlatformSudo
// narrowed to a HUMAN, and it is the predicate BOTH org questions branch on
// (EffectiveOrg: which org the request acts in; LedgerOrg: which org pays).
//
// The human narrowing is load-bearing, not decoration: without it ANY admin-org
// client_credentials app — the KMS sync identity, say — could name a victim org in
// X-Org-Id and the edge would mint it, handing every gateway-fronted backend
// (which trusts the minted header by design) a cross-tenant read. Mirrors cloud's
// SuperAdmin arm (owner == adminOrg && !isMachinePrincipal).
func (c *Claims) Masquerade() bool {
	return c.PlatformSudo() && !c.Machine()
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

// MintedBillingAccount returns the account that PAYS, to stamp into
// X-Billing-Account-Id, or "" when the edge must OMIT the header. It rides in the
// validated JWT `billing_account` claim, scoped to the caller's org exactly like
// `project` — trusted, not forgeable.
//
// It is AUTHORITATIVE, not a hint. IAM resolves who pays at the identity boundary
// from the real grant context and signs it (iam/object/billing_account.go); the
// wire is `<kind>:<subject>` and ai/object.Payer reads it back into the Account it
// debits. So this is money: the strip on ingress is a security control, not
// hygiene — a surviving client copy is a caller naming its own payer.
//
// Unlike the project claim there is NO reserved default: an absent/empty account
// mints nothing. That is a token minted before the claim shipped (or one IAM could
// not attribute), and Payer's legacy rule answers for it — billing the account it
// always did, never nothing.
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
// the gin/Lura middleware. Forwards-only: append new client_ids, never
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
		JWKSURL:   envOr("AUTH_JWKS_URL", "https://hanzo.id/v1/iam/.well-known/jwks"),
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
//   - X-Billing-Account-Id: WHO PAYS, minted from a validated claim; a raw client
//     value is a caller naming its own payer (Payer debits what this names).
//
// The legacy vendor-prefixed identity headers (X-IAM-Org-Id, X-Hanzo-Org, …) have
// been RENAMED to these neutral names at every setter + consumer, so no identity
// header uses a vendor prefix anymore — which is exactly what lets the ingress
// (Traefik, exact-name only) strip the FULL identity set with no wildcard gap.
var StripIdentityHeaderNames = []string{
	"X-User-Id",
	OrgHeader,
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

// OrgHeader is the ONE org header, and it plays two roles across the trust
// boundary — inbound it is the client's SELECTION (which org the switcher picked),
// outbound it is the edge's minted AUTHORITY (which org the request acts in).
// StripIdentityHeaders performs the conversion between the two in one act: it
// returns the selection and deletes the header, so what a client sent survives
// only as an INTENT, and only EffectiveOrg can turn an intent back into authority.
//
// There is no second org header. An earlier design routed the intent through a
// separate X-Act-As-Org while cloud read the selection from X-Org-Id; no client
// ever sent it, so the edge's membership gate ran on "" for every request and
// always resolved home — a correct gate wired to nothing. One name, one meaning.
const OrgHeader = "X-Org-Id"

// StripIdentityHeaders removes every client-supplied identity header (exact neutral
// names) plus, defensively, any stray vendor-prefixed header, and RETURNS the org
// the client selected (the inbound OrgHeader). The edge is the sole authority for
// identity; this MUST run before any bypass path so a forged value can never
// survive.
//
// The capture and the strip are ONE operation on purpose. The selection has to be
// read BEFORE the header is deleted, and a separate "read it first" function would
// be an ordering trap that fails silently — the switch would just stop working. By
// threading the selection through the return value the ordering is impossible to
// get wrong, and a caller that ignores it (the unauthenticated paths) simply keeps
// today's behavior: nothing minted, nothing trusted.
func StripIdentityHeaders(r *http.Request) string {
	selected := r.Header.Get(OrgHeader)
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
	return selected
}

// InjectIdentity sets the core identity headers from validated claims. This
// is the minimal edge identity (id, org, email, isAdmin) — roles and the
// permission bit-field stay in the commerce-coupled gateway middleware.
// Call StripIdentityHeaders first and pass its return value as selected.
func InjectIdentity(r *http.Request, c *Claims, selected string) {
	r.Header.Set("X-User-Id", c.UserID())
	// X-Org-Id = the EFFECTIVE org: the org the client SELECTED when the signed
	// membership set admits it (or the operator may masquerade), else the home org.
	// The client's copy was already deleted by StripIdentityHeaders, so the value
	// re-minted here is authority, never passthrough.
	effective, _ := c.EffectiveOrg(selected)
	r.Header.Set(OrgHeader, effective)
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
