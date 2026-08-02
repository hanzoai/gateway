package gateway

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"

	"github.com/hanzoai/authz"
	"github.com/hanzoai/authz/edge"
	"github.com/hanzoai/gateway/v2/token"
)

// The HTTP edge's identity, applied from the one place that decides it.
//
// This file used to be a shim over a gateway-local copy of the whole contract —
// claims, org resolution, the two admin scopes, the header lists. That copy drifted
// from the estate's and the drift was live: the platform-authority header was written
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
// It is brand-NEUTRAL in effect because it only ever DELETES — never writes, never
// requires — so it stays correct on every deployment this edge fronts.
var vendorPrefixes = []string{"X-IAM-", "X-HANZO-"}

// Headers is a header set this edge can strip, write and ENUMERATE.
//
// edge.Headers is the estate's minimum — Get/Set/Del — and it is deliberately
// that small, so a transport qualifies by shape rather than by being named.
// The vendor-prefix backstop below needs one thing more: the NAMES present,
// which cannot be expressed in Get/Set/Del and is spelled differently by every
// transport (a Go map ranges, fasthttp visits). So the enumeration is added
// here, in the one package that needs it, and each transport supplies it in a
// line or two.
type Headers interface {
	edge.Headers
	// Names calls fn once per header name on the request. Implementations must
	// tolerate fn deleting the name it was handed.
	Names(fn func(name string))
}

// httpHeaders adapts net/http's header map — the shape the gin transport and
// every test carry. http.Header already satisfies edge.Headers with no adapter
// at all, so this adds only the enumeration.
type httpHeaders struct{ http.Header }

func (h httpHeaders) Names(fn func(string)) {
	for name := range h.Header {
		fn(name)
	}
}

// fastHeaders adapts a zip request's headers — fasthttp's, where reading
// returns bytes. The Get/Set/Del third is edge.Of, the estate's OWN adapter for
// exactly this shape (documented on edge.Peeker as the way to reach a zip
// request's headers), so this type states only the enumeration.
type fastHeaders struct {
	edge.Headers
	raw *fasthttp.RequestHeader
}

// newFastHeaders wraps a fasthttp request header set as [Headers].
func newFastHeaders(h *fasthttp.RequestHeader) fastHeaders {
	return fastHeaders{Headers: edge.Of(h), raw: h}
}

// Names visits the request's header names. The names are COLLECTED before fn
// runs: fasthttp's VisitAll walks the live slice, and deleting during that walk
// skips the element after the deleted one — which would leave a forgeable
// header on the request precisely when two of them were adjacent.
func (f fastHeaders) Names(fn func(string)) {
	names := make([]string, 0, f.raw.Len())
	f.raw.VisitAll(func(k, _ []byte) { names = append(names, string(k)) })
	for _, n := range names {
		fn(n)
	}
}

// stripClaimed deletes every identity header a client supplied and returns the org
// it CLAIMED. Two strips, one call: the estate's exact-name contract (edge.Strip)
// and this transport's vendor-prefix backstop.
//
// They are one function because two would be an ordering trap — a caller that
// remembered the first and forgot the second would leave forgeable junk on the
// request, and nothing would fail. The prefix sweep cannot live in the estate's
// edge: it must ENUMERATE header names, which is transport-specific, while
// edge.Headers is deliberately just Get/Set/Del.
func stripClaimed(h Headers) string {
	claimed := edge.Strip(h)
	h.Names(func(name string) {
		upper := strings.ToUpper(name)
		for _, p := range vendorPrefixes {
			if strings.HasPrefix(upper, p) {
				h.Del(name)
				return
			}
		}
	})
	return claimed
}

// writeIdentity writes the identity a verified token earns onto the request the
// backend will read, then adds the one header whose meaning is this gateway's
// rather than the estate's.
//
// selected is the org the client asked for, as returned by [edge.Strip]. It is
// honoured only where the signed membership set admits it.
func writeIdentity(h edge.Headers, claims *authz.Claims, selected string) {
	edge.Apply(h, claims, selected, nil)

	// X-User-Permissions is the MONEY authority commerce gates on: it reads this
	// bit-field and bit.Field.Has is intersection semantics, so whoever carries Admin
	// satisfies every credit-creating and card-charging endpoint. It is therefore
	// PLATFORM-sudo only — granting it to an org owner was a live free-money hole.
	//
	// It is written here rather than by edge.Render because the bit VOCABULARY is this
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
