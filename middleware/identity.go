package middleware

import (
	"github.com/hanzoai/gateway/v2/iamauth"
	"github.com/zap-proto/zip"
)

// StripIdentityHeaders deletes every client-supplied identity header before any
// other middleware runs. Per HIP-0026, only the gateway-minted path is trusted;
// everything else must be stripped so a client can never forge an identity a
// backend would read.
//
// The set is iamauth.StripIdentityHeaderNames — the SAME authoritative list the
// gateway middleware and the ingress strip from, so the copies cannot drift. It
// covers the org SUB-SCOPE selectors (X-Project-Id, X-Billing-Account-Id) and
// X-User-Owner as well as X-Org-Id: a forged sub-scope selects another tenant's
// project or names a funding account, so a hand-picked subset is a hole the moment a
// backend reads one of the omitted names (HIP-0111).
//
// Use this when a service runs WITHOUT a Hanzo gateway in front (rare). When
// deployed behind hanzoai/gateway, the gateway strips these unconditionally and
// re-mints from the JWT — leave this middleware OFF in that topology.
func StripIdentityHeaders() zip.Handler {
	return func(c *zip.Ctx) error {
		req := c.Fiber().Request()
		for _, h := range iamauth.StripIdentityHeaderNames {
			req.Header.Del(h)
		}
		// The act-as INTENTS are inputs to a mint this topology does not perform, so
		// here they are pure client input with no seam to authorize them: drop them.
		for _, h := range iamauth.ActAsHeaderNames {
			req.Header.Del(h)
		}
		return c.Continue()
	}
}
