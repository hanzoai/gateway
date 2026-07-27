package gateway

import (
	"net/http"
	"time"

	"github.com/hanzoai/gateway/v2/iamauth"
)

// These shims keep the gin/Lura auth middleware (and its security tests)
// on the single edge-auth implementation in package iamauth. The middleware
// keeps its commerce-coupled glue (billing, permission bit-fields, role
// minting); everything below is delegated so there is exactly one copy of
// the JWKS cache, JWT validation, token extraction, and the identity-header
// trust boundary.

type jwksCache = iamauth.JWKSCache
type hanzoJWTClaims = iamauth.Claims

func newJWKSCache(url string, ttl time.Duration) *jwksCache { return iamauth.NewJWKSCache(url, ttl) }

func validateToken(raw string, cache *jwksCache, issuer string, audiences []string) (*hanzoJWTClaims, error) {
	return iamauth.ValidateToken(raw, cache, issuer, audiences)
}

func stripIdentityHeaders(r *http.Request) string   { return iamauth.StripIdentityHeaders(r) }
func isAPIKey(token string) bool                    { return iamauth.IsAPIKey(token) }
func extractBearerToken(r *http.Request) string     { return iamauth.BearerToken(r) }
func extractTokenFromCookie(r *http.Request) string { return iamauth.CookieToken(r) }

// gatewayMintedIdentityHeaders is the authoritative list of identity headers
// the gateway may emit downstream; every entry MUST also be stripped on
// ingress (iamauth.StripIdentityHeaders). The contract test in
// auth_middleware_security_test.go enforces strip ⊇ mint.
var gatewayMintedIdentityHeaders = iamauth.MintedIdentityHeaders
