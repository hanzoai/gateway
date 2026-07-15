// Copyright © 2026 Hanzo AI. MIT License.

package gateway

import "strings"

// brandForHost resolves a request Host to its white-label brand id for the
// Server response header. The gateway is the shared multi-brand edge — it fronts
// api.hanzo.ai, api.lux.network, api.zoo.ngo, ... from one binary — so the Server
// header cannot be a single hardcoded brand; it must be the brand of the request
// Host, or a neutral default when no brand domain matches.
//
// A Host at or under a brand's registrable domain resolves to that brand; the
// longest matching domain wins; the port is stripped and the compare is
// case-insensitive. Returns "" when nothing matches, so the caller supplies its
// own neutral default (NeutralServerBrand).
//
// This mirrors the canonical platform registry in hanzoai/cloud (brand.go /
// BrandForHostOK). The gateway keeps its own copy because its pinned cloud does
// not yet export BrandForHostOK and, more fundamentally, zip's white-label
// middleware rides the zap-proto/fiber fork that the pinned cloud predates — a
// coordinated cloud+zip bump is out of scope for a response-header change. When
// that alignment lands (or a shared brand module is extracted) this folds into
// that one home.
func brandForHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	// A fully-qualified Host may carry a trailing root dot ("api.lux.network.");
	// strip it so the suffix match still resolves the brand instead of failing to
	// neutral. Mirrors cloud/brand.go BrandForHostOK.
	host = strings.TrimSuffix(host, ".")
	best, bestLen := "", -1
	for _, bd := range brandDomains {
		if (host == bd.domain || strings.HasSuffix(host, "."+bd.domain)) && len(bd.domain) > bestLen {
			best, bestLen = bd.brand, len(bd.domain)
		}
	}
	return best
}

// brandDomains mirrors cloud/brand.go's per-brand Domain + AltDomains.
var brandDomains = []struct{ brand, domain string }{
	{"hanzo", "hanzo.ai"}, {"hanzo", "hanzo.cloud"}, {"hanzo", "hanzo.app"},
	{"lux", "lux.network"}, {"lux", "lux.cloud"},
	{"zoo", "zoo.ngo"}, {"zoo", "zoo.network"}, {"zoo", "zoo.cloud"},
	{"pars", "pars.network"}, {"pars", "pars.ai"},
	{"bootnode", "bootno.de"},
}

// NeutralServerBrand is the Server value when a request Host matches no brand
// (internal k8s probes, direct-IP hits). Brand-neutral and honest about the role
// without ever naming the framework (fasthttp / fiber / zip / KrakenD).
const NeutralServerBrand = "gateway"

// hstsPolicy is the Strict-Transport-Security value: two years, subdomains
// included — the Stripe/Cloudflare/GitHub production floor.
const hstsPolicy = "max-age=63072000; includeSubDomains"
