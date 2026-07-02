package middleware

import (
	"github.com/zap-proto/zip"
)

// StripIdentityHeaders strips client-supplied X-Org-Id / X-User-Id /
// X-User-Email / X-User-IsAdmin / X-Roles / X-User-Permissions from the
// request before any other middleware runs. Per HIP-0026, only the
// gateway-minted path is trusted; everything else must be stripped to
// prevent client spoofing.
//
// Use this when a service runs WITHOUT a Hanzo gateway in front (rare).
// When deployed behind hanzoai/gateway, the gateway strips these
// unconditionally and re-mints from JWT — leave this middleware OFF in
// that topology.
func StripIdentityHeaders() zip.Handler {
	return func(c *zip.Ctx) error {
		req := c.Fiber().Request()
		req.Header.Del("X-Org-Id")
		req.Header.Del("X-User-Id")
		req.Header.Del("X-User-Email")
		req.Header.Del("X-User-IsAdmin")
		req.Header.Del("X-Roles")
		req.Header.Del("X-User-Permissions")
		return c.Continue()
	}
}
