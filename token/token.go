// Package token is the gateway's credential check: which issuer it trusts, which
// audiences it accepts, and the keys it verifies against.
//
// It is deliberately thin. The identity DECISION — what a claim means, which org a
// request acts in, who pays, which headers get minted — lives in hanzoai/authz and
// hanzoai/authz/edge, because three consumers each having their own reading of one
// contract is what drifted into a live escalation. What is left here is the part
// that is genuinely this deployment's: the ISSUER and AUDIENCE policy, named by the
// environment variables this deployment already sets.
package token

import (
	"os"
	"strings"
	"time"

	"github.com/hanzoai/authz/edge"
)

// Config is the edge's verification policy.
type Config struct {
	JWKSURL string

	// Issuers is the trusted-issuer allowlist. It is a SET because one deployment
	// fronts several brands, each signing under its own issuer; an empty set refuses
	// every token rather than silently disabling the check.
	Issuers []string

	// Audiences is the allowlist of acceptable `aud` values, with OR semantics: a
	// token passes when its audience matches ANY entry.
	//
	// It is enforced HERE rather than in authz.Verify, which deliberately does not
	// check audience — IAM sets `aud` per RFC 8707 to the requesting CLIENT, so the
	// claim names which client asked for the token, not which resource server may
	// accept it. Checking it is therefore a POLICY an edge may hold ("I accept tokens
	// minted for these consoles") and not part of reading a token. An empty list
	// disables the check; AudiencesFromEnv never returns empty, so it is always on.
	Audiences []string

	JWKSTTL time.Duration
}

// DefaultAudiences is the baked allowlist: the known IAM client_ids (each app's
// `aud` is its client_id) plus the API origin. Forwards-only — append a new
// client_id, never remove one. Override entirely with GATEWAY_ALLOWED_AUDIENCES.
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
// baked list is used, with the legacy single-value AUTH_AUDIENCE folded IN when set
// — it widens, never narrows, so a deployment still pinned to AUTH_AUDIENCE keeps
// that value inside an already-inclusive set rather than collapsing the allowlist to
// one entry. The result is never empty, so the check is always enforced.
func AudiencesFromEnv() []string {
	if v := os.Getenv("GATEWAY_ALLOWED_AUDIENCES"); v != "" {
		if list := split(v); len(list) > 0 {
			return list
		}
	}
	out := append([]string(nil), DefaultAudiences...)
	if legacy := strings.TrimSpace(os.Getenv("AUTH_AUDIENCE")); legacy != "" {
		if !accepts(out, legacy) {
			out = append(out, legacy)
		}
	}
	return out
}

// ConfigFromEnv reads the AUTH_* variables, so every binary in this module agrees
// on the IAM authority.
func ConfigFromEnv() Config {
	return Config{
		JWKSURL:   envOr("AUTH_JWKS_URL", "https://hanzo.id/v1/iam/.well-known/jwks"),
		Issuers:   IssuersFromEnv(),
		Audiences: AudiencesFromEnv(),
		JWKSTTL:   15 * time.Minute,
	}
}

// IssuersFromEnv resolves the trusted-issuer allowlist: AUTH_ISSUER (the primary),
// widened by WHITELABEL_ISSUERS (comma-separated) so a brand this edge fronts can be
// added without a code change. It never returns empty, so the check is always on.
func IssuersFromEnv() []string {
	out := []string{envOr("AUTH_ISSUER", "https://hanzo.id")}
	for _, iss := range split(os.Getenv("WHITELABEL_ISSUERS")) {
		if !accepts(out, iss) {
			out = append(out, iss)
		}
	}
	return out
}

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

func split(s string) []string {
	out := make([]string, 0, 4)
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// accepts reports whether want is in the allowlist. The comparison is VERBATIM, for
// the same reason every identifier comparison in authz is: folding case would make
// two registered client ids one.
func accepts(allow []string, want string) bool {
	for _, a := range allow {
		if a == want {
			return true
		}
	}
	return false
}

// NewValidator builds the edge's verifier from cfg. The check itself lives in
// hanzoai/authz/edge — this package's whole job is turning THIS deployment's
// environment into the values it takes, which is the only part that is ours.
func NewValidator(cfg Config) *edge.Verifier {
	return edge.NewVerifier(cfg.JWKSURL, cfg.Issuers, cfg.Audiences, cfg.JWKSTTL)
}

// ErrNoToken is the edge's sentinel, re-exported so a caller that already imports
// this package for its config can compare against it without importing the edge for
// one variable. It is the same value, not a copy.
var ErrNoToken = edge.ErrNoToken
