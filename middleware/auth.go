// Package middleware ships gateway-owned middleware for the zip web
// framework. JWT validation + identity-header stripping live here (and
// NOT in github.com/zap-proto/zip/middleware) because they are the
// gateway subsystem's responsibility per HIP-0106.
//
// Other subsystems mounted inside the unified cloud binary trust the
// gateway-minted X-Org-Id header and do not re-validate JWTs
// themselves — re-running JWT validation per-subsystem is wasteful and
// risks divergent validation rules.
package middleware

import (
	"context"
	"strings"

	"github.com/zap-proto/zip"

	gateway "github.com/hanzoai/gateway/v2"
)

// AuthVerifier is the interface Auth() consumes. The real implementation
// in hanzoai/iam or hanzoai/gateway-sdk satisfies it. A nil verifier on
// a request that has no gateway X-* headers and no Authorization bearer
// is rejected with 401.
type AuthVerifier interface {
	// Verify validates the bearer token and returns the canonical
	// X-* headers to mint (Org / User / Email / IsAdmin / Roles).
	Verify(ctx context.Context, bearer string) (Identity, error)
}

// Identity is the validated identity payload returned by AuthVerifier.
type Identity struct {
	Org       string
	User      string
	UserEmail string
	IsAdmin   bool
	Roles     []string
}

// Auth validates incoming requests via verifier. When the request already
// carries gateway-minted X-Org-Id (i.e. behind hanzoai/gateway), the
// verifier is bypassed and the headers are trusted. Otherwise the
// Authorization: Bearer <token> is verified.
//
// On successful gateway-trust or successful in-process verification,
// Auth marks the request as gateway-minted via SetGatewayMinted so
// downstream subsystems can assert the trust boundary with
// gateway.AssertGatewayMinted(c).
//
// Pass a nil verifier to only accept gateway-minted headers (no in-binary
// JWT validation).
func Auth(verifier AuthVerifier) zip.Handler {
	return func(c *zip.Ctx) error {
		// Trust the gateway path first.
		if c.Org() != "" || c.User() != "" {
			gateway.SetGatewayMinted(c)
			return c.Continue()
		}
		if verifier == nil {
			return zip.ErrUnauthorized("authentication required")
		}
		raw := c.Header("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			return zip.ErrUnauthorized("missing bearer token")
		}
		id, err := verifier.Verify(c.Context(), raw[len("Bearer "):])
		if err != nil {
			return zip.ErrUnauthorized("invalid token")
		}
		// Mint the validated headers so handlers see the same shape as
		// the gateway-fronted path.
		req := c.Fiber().Request()
		req.Header.Set("X-Org-Id", id.Org)
		req.Header.Set("X-User-Id", id.User)
		req.Header.Set("X-User-Email", id.UserEmail)
		if id.IsAdmin {
			req.Header.Set("X-User-IsAdmin", "true")
		}
		if len(id.Roles) > 0 {
			req.Header.Set("X-Roles", strings.Join(id.Roles, ","))
		}
		gateway.SetGatewayMinted(c)
		return c.Continue()
	}
}
