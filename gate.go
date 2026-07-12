// Copyright © 2026 Hanzo AI. Apache-2.0 License.

// gate.go is the gateway relay's authn policy, run on every inbound
// Forward ENVELOPE per HIP-0110. It is the edge trust boundary: the gate
// validates the IAM JWT carried in the Forward's headers and stamps the
// resolved identity (TenantID/UserID/IsAdmin/Permissions) onto the
// envelope so the backend trusts the edge. forward.Relay then re-emits
// the Forward with that identity and ships it to the chosen backend.
//
// One auth implementation: the gate reuses package iamauth (the same
// JWKS cache + JWT validation + token extraction shared with cmd/ingress
// and the gin/KrakenD middleware) and gateway's own permission bit-field
// math (computePermissionsBitField / permissionBits). No second copy.
//
// Billing is NOT enforced here. The gateway is authn + identity injection
// only; cloud's own prepaid balance gate bills the bridged request.
// This split is deliberate (HIP-0110): the relay must not read f.Body and
// must not block on a per-request Commerce round-trip — it stamps identity
// and forwards. The gate therefore touches f.Path and f.Headers only.
package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/luxfi/zap/forward"

	"github.com/hanzoai/gateway/v2/iamauth"
)

// newGate builds the forward.Gate from an AuthConfig. The JWKS cache is
// constructed once and captured by the returned closure, so repeated
// Forwards reuse cached signing keys (TTL-refreshed, stale-on-error) just
// like the gin middleware.
//
// Policy (identical to NewAuthMiddleware, the established one way):
//   - public path  -> allow, no identity (health, .well-known, favicon…)
//   - no token      -> allow with no identity, UNLESS cfg.RequireAuth, in
//     which case deny 401 (the edge is the authn boundary)
//   - API key       -> allow, no JWT identity (validated downstream by the
//     backend: cloud, commerce, base…)
//   - invalid JWT   -> deny 401
//   - valid JWT      -> inject identity, allow
//
// On allow the gate mutates f's identity fields in place and returns
// (nil, nil). On deny it returns a non-nil *forward.Response carrying a
// clean HTTP status + JSON error so the client sees a real response. It
// never returns a non-nil error for ordinary policy rejection (that would
// fail the caller's Call instead of yielding an HTTP status).
func newGate(cfg AuthConfig) forward.Gate {
	// Auth disabled (AUTH_ENABLED=false): forward everything with no edge
	// identity, same pass-through the gin middleware does in dev/test. No
	// JWKS cache is constructed.
	if !cfg.Enabled {
		return func(context.Context, *forward.Forward) (*forward.Response, error) {
			return nil, nil
		}
	}

	cache := newJWKSCache(cfg.JWKSURL, jwksTTL)

	publicPaths := cfg.PublicPaths

	return func(_ context.Context, f *forward.Forward) (*forward.Response, error) {
		// Trust boundary: clear any inbound envelope identity FIRST, before
		// any allow path. forward.Forwarder lifts a client's X-Org-Id /
		// X-User-Id headers into f.TenantID / f.UserID; only a validated JWT
		// may re-assert them. This is the relay's counterpart to the gin
		// middleware's StripIdentityHeaders — a forged identity can never
		// survive on the no-token, API-key, public, or invalid-token paths.
		f.TenantID = ""
		f.UserID = ""
		f.IsAdmin = false
		f.Permissions = 0

		// Public paths bypass auth entirely — same prefix match the gin
		// middleware uses. f.Path carries the raw query inline; prefix
		// match is on the leading path which is unaffected by a query.
		for _, pp := range publicPaths {
			if pp != "" && strings.HasPrefix(f.Path, pp) {
				return nil, nil
			}
		}

		token := tokenFromForward(f)
		if token == "" {
			if cfg.RequireAuth {
				return denyJSON(http.StatusUnauthorized, "unauthorized",
					"Authentication required"), nil
			}
			// No credential: forward with no edge identity. The backend
			// applies its own policy (and cloud its balance gate).
			return nil, nil
		}

		// Opaque API keys (hk-/sk-/fw_/hz_/pk-) are validated by the
		// backend service directly, not as a JWT here. Pass them through
		// with no edge identity, exactly like the gin middleware.
		if isAPIKey(token) {
			return nil, nil
		}

		claims, err := validateToken(token, cache, cfg.Issuer, cfg.Audiences)
		if err != nil {
			return denyJSON(http.StatusUnauthorized, "unauthorized",
				"Invalid token"), nil
		}

		// Inject the validated identity onto the envelope in place. These
		// are the only fields the gate mutates; it never touches f.Body.
		f.TenantID = claims.Owner
		f.UserID = claims.UserID()
		f.IsAdmin = claims.IsAdmin

		// X-User-Permissions bit-field (same policy as the gin middleware and
		// gate — one grant rule, three transports). The Admin (money/admin)
		// bit is GLOBAL-admin-only: commerce gates every credit-creating and
		// card-charging billing endpoint on TokenRequired(permission.Admin),
		// so granting Admin to an org-level admin (claims.IsAdmin — an org
		// owner) was a free-money hole. Live (real-money mode) is orthogonal
		// and stays on IsAdmin. The explicit "permissions" claim is OR'd on
		// top. Absent/unmapped -> 0, which the backend reads as no rights.
		var extraBits int64
		if claims.IsAdmin {
			extraBits |= permissionBits["live"]
		}
		// Platform-sudo money/admin authority = home org is the reserved admin org.
		if claims.PlatformSudo() {
			extraBits |= permissionBits["admin"]
		}
		bits, _ := computePermissionsBitField(claims.Permissions, extraBits)
		f.Permissions = bits

		return nil, nil
	}
}

// tokenFromForward extracts the IAM credential from the Forward's headers
// using the canonical iamauth extraction (Bearer / HTTP Basic password /
// session cookie incl. iam_access_token). It reconstructs a throwaway
// *http.Request from f.Headers — the JSON map[string][]string canonical
// header set — and delegates to iamauth.ExtractToken so there is exactly
// one extraction implementation. It reads f.Headers ONLY; never f.Body.
func tokenFromForward(f *forward.Forward) string {
	if len(f.Headers) == 0 {
		return ""
	}
	var hdrs map[string][]string
	if err := json.Unmarshal(f.Headers, &hdrs); err != nil {
		return ""
	}
	return iamauth.ExtractToken(&http.Request{Header: http.Header(hdrs)})
}

// denyJSON builds a deny *forward.Response with a JSON error body and the
// JSON content-type header, so the short-circuited client sees a clean
// HTTP error instead of a bare status.
func denyJSON(status int, errCode, message string) *forward.Response {
	body, _ := json.Marshal(map[string]string{"error": errCode, "message": message})
	hdrs, _ := json.Marshal(map[string][]string{
		"Content-Type": {"application/json"},
	})
	return &forward.Response{Status: status, Body: body, Headers: hdrs}
}

// isBasePath reports whether a request path routes to the base backend.
// This is the single definition of the base/cloud split — both the static
// pickPeer (tests) and the lazy peerResolver.picker (production) consult it,
// so the routing rule lives in exactly one place.
func isBasePath(path string) bool {
	return strings.HasPrefix(path, "/v1/base/")
}

// pickPeer routes a Forward by path: /v1/base/* -> the base peer NodeID,
// everything else -> the cloud peer NodeID. The NodeIDs are the
// handshake-learned ids of the already-connected peers (captured at dial
// time via ConnectDirectID), so forward.Relay's node.Call resolves them
// against the existing connections.
//
// This static form is used where the peerIDs are known up front (tests).
// Production uses peerResolver.picker, which dials lazily and shares the
// same isBasePath routing rule.
func pickPeer(basePeerID, cloudPeerID string) forward.PeerPicker {
	return func(path string) string {
		if isBasePath(path) {
			return basePeerID
		}
		return cloudPeerID
	}
}
