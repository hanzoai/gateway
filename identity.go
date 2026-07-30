package gateway

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/gateway/v2/token"
)

// The HTTP edge's identity, applied from the one place that decides it.
//
// This file used to be a shim over a gateway-local copy of the whole contract —
// claims, org resolution, the two admin scopes, the header lists. That copy drifted
// from the estate's and the drift was live: the platform-authority header was minted
// from Claims.IsAdmin, IAM's ORG-role bit, so every org owner arrived a platform
// admin. The zip edge had already been corrected; this one had not, because there
// were two statements of one rule.
//
// Now there is one. hanzoai/authz says what a claim means, hanzoai/authz/edge says
// which headers a verified token earns, and net/http's own header type satisfies
// edge.Headers — so applying it here is a loop, not a second implementation.

// vendorPrefixes are header families no identity contract uses and no backend
// should trust. Stripping them is DEFENSE IN DEPTH, not the contract: every
// identity header is brand-neutral and named exactly in authz.Headers, so this
// catches only stray vendor junk a backend might someday read.
//
// It is brand-NEUTRAL in effect because it only ever DELETES — never mints, never
// requires — so it stays correct on every deployment this edge fronts.
var vendorPrefixes = []string{"X-IAM-", "X-HANZO-"}

// stripClaimed deletes every identity header a client supplied and returns the org
// it CLAIMED. Two strips, one call: the estate's exact-name contract (edge.Strip)
// and this transport's vendor-prefix backstop.
//
// They are one function because two would be an ordering trap — a caller that
// remembered the first and forgot the second would leave forgeable junk on the
// request, and nothing would fail. The prefix sweep cannot live in the estate's
// edge: it must ENUMERATE header names, which is transport-specific, while
// edge.Headers is deliberately just Get/Set/Del.
func stripClaimed(h http.Header) string {
	claimed := edge.Strip(h)
	for name := range h {
		upper := strings.ToUpper(name)
		for _, p := range vendorPrefixes {
			if strings.HasPrefix(upper, p) {
				h.Del(name)
				break
			}
		}
	}
	return claimed
}

// mintIdentity applies the identity a verified token earns to the request the
// backend will read, then adds the one header whose meaning is this gateway's
// rather than the estate's.
//
// selected is the org the client asked for, as returned by [edge.Strip]. It is
// honoured only where the signed membership set admits it.
func mintIdentity(h edge.Headers, claims *authz.Claims, selected string) {
	edge.Apply(h, claims, selected, nil)

	// X-User-Permissions is the MONEY authority commerce gates on: it reads this
	// bit-field and bit.Field.Has is intersection semantics, so whoever carries Admin
	// satisfies every credit-creating and card-charging endpoint. It is therefore
	// PLATFORM-sudo only — granting it to an org owner was a live free-money hole.
	//
	// It is minted here rather than by edge.Mint because the bit VOCABULARY is this
	// deployment's commerce contract, not part of what an identity is. The name is in
	// the strip set either way, so a client copy never survives to be trusted.
	//
	// `live` (real-money rather than sandbox) is orthogonal to authority and stays on
	// the org-role bit, so an org owner's own real top-up keeps working.
	if bits := moneyBits(claims); bits != 0 {
		h.Set(authz.HeaderUserPermissions, strconv.FormatInt(bits, 10))
	}
}

// moneyBits is the permission bit-field a verified token earns — ONE rule, read by
// the HTTP edge (as a header) and by the ZAP relay (as an envelope field), so the
// two transports cannot come to different conclusions about who may spend.
//
// The ADMIN bit is PLATFORM sudo only. Commerce gates every credit-creating and
// card-charging endpoint on it with intersection semantics, so an org owner holding
// it was a free-money hole. LIVE (real money rather than sandbox) is orthogonal to
// authority and stays on the org-role bit, so an org owner's own real top-up works.
func moneyBits(claims *authz.Claims) int64 {
	if claims == nil {
		return 0
	}
	var bits int64
	if claims.IsAdmin {
		bits |= permissionBits["live"]
	}
	if claims.PlatformSudo() {
		bits |= permissionBits["admin"]
	}
	return bits
}

// extraIssuers returns the white-label issuers beyond the primary, deduped.
func extraIssuers(primary string) []string {
	var out []string
	for _, iss := range token.IssuersFromEnv() {
		if iss != primary {
			out = append(out, iss)
		}
	}
	return out
}

// validator is the credential check, built once per middleware from AuthConfig.
func newValidator(cfg AuthConfig) *edge.Verifier {
	return token.NewValidator(token.Config{
		JWKSURL: cfg.JWKSURL,
		// The AuthConfig carries one issuer (its env var is singular); the verifier takes
		// the allowlist, widened by WHITELABEL_ISSUERS so a brand this edge fronts is
		// added by configuration rather than by a code change.
		Issuers:   append([]string{cfg.Issuer}, extraIssuers(cfg.Issuer)...),
		Audiences: cfg.Audiences,
		JWKSTTL:   jwksTTL,
	})
}
