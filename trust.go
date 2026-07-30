// Copyright © 2026 Hanzo AI. Apache-2.0 License.

package gateway

import (
	"github.com/zap-proto/zip"
)

// gatewayWrittenKey is the zip.Ctx Locals key under which gateway's auth
// middleware records "this request flowed through me and the X-Org-Id
// header is gateway-validated, not client-supplied". Type is unexported
// so subsystem code cannot forge a collision.
type gatewayWrittenKey struct{}

// SetGatewayWritten marks the current request as gateway-written. Called
// by gateway's auth middleware after successful JWT validation (or
// trusted-headers pass-through). Subsystems must NEVER call this — it
// is the trust boundary itself.
func SetGatewayWritten(c *zip.Ctx) {
	c.Locals(gatewayWrittenKey{}, true)
}

// AssertGatewayWritten returns true iff the request flowed through
// gateway's auth middleware (i.e. X-Org-Id was written by gateway, not
// supplied by the client).
//
// Implementation: gateway middleware sets a per-request Locals key
// after JWT validation. AssertGatewayWritten reads that key.
//
// In production, every cloud-mounted subsystem should reject any
// request where AssertGatewayWritten returns false (HTTP 502 with a
// clear message — it indicates a deployment misconfiguration, not a
// client problem).
func AssertGatewayWritten(c *zip.Ctx) bool {
	v := c.Locals(gatewayWrittenKey{})
	if v == nil {
		return false
	}
	written, _ := v.(bool)
	return written
}
