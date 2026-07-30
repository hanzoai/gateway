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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
)

// Config is the edge's verification policy.
type Config struct {
	JWKSURL string
	Issuer  string

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

// ErrNoToken reports that no credential was present, so a caller can tell "missing"
// from "invalid" and fall through to a session or anonymous path.
var ErrNoToken = errors.New("token: no credential")

// Validator binds a Config to the edge's key cache for repeated verification.
type Validator struct {
	cfg  Config
	keys *edge.Keys
}

// NewValidator builds a Validator from cfg.
func NewValidator(cfg Config) *Validator {
	return &Validator{cfg: cfg, keys: edge.NewKeys(cfg.JWKSURL, cfg.JWKSTTL)}
}

// Verify extracts the credential a request carries and verifies it.
func (v *Validator) Verify(h edge.Headers) (*authz.Claims, error) {
	return v.VerifyRaw(edge.Token(h))
}

// VerifyRaw verifies a credential held out of band — an OAuth2 code-exchange
// handler checking the token it just received, say.
//
// Signature, issuer and expiry are authz.Verify's; the audience allowlist is this
// edge's, applied after. The order matters: an unverified token's claims are not
// evidence of anything, so nothing is read off it before the signature holds.
func (v *Validator) VerifyRaw(raw string) (*authz.Claims, error) {
	if raw == "" {
		return nil, ErrNoToken
	}
	claims, err := authz.Verify(raw, v.keys.Resolve, v.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	if len(v.cfg.Audiences) == 0 {
		return claims, nil
	}
	for _, aud := range claims.Audience {
		if accepts(v.cfg.Audiences, aud) {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("token: audience %v is not accepted here", []string(claims.Audience))
}
