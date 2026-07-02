// Copyright © 2026 Hanzo AI. MIT License.

package gateway

import (
	"github.com/zap-proto/zip"
)

// gatewayMintedKey is the zip.Ctx Locals key under which gateway's auth
// middleware records "this request flowed through me and the X-Org-Id
// header is gateway-validated, not client-supplied". Type is unexported
// so subsystem code cannot forge a collision.
type gatewayMintedKey struct{}

// SetGatewayMinted marks the current request as gateway-minted. Called
// by gateway's auth middleware after successful JWT validation (or
// trusted-headers pass-through). Subsystems must NEVER call this — it
// is the trust boundary itself.
func SetGatewayMinted(c *zip.Ctx) {
	c.Locals(gatewayMintedKey{}, true)
}

// AssertGatewayMinted returns true iff the request flowed through
// gateway's auth middleware (i.e. X-Org-Id was minted by gateway, not
// supplied by the client).
//
// Implementation: gateway middleware sets a per-request Locals key
// after JWT validation. AssertGatewayMinted reads that key.
//
// In production, every cloud-mounted subsystem should reject any
// request where AssertGatewayMinted returns false (HTTP 502 with a
// clear message — it indicates a deployment misconfiguration, not a
// client problem).
func AssertGatewayMinted(c *zip.Ctx) bool {
	v := c.Locals(gatewayMintedKey{})
	if v == nil {
		return false
	}
	minted, _ := v.(bool)
	return minted
}
