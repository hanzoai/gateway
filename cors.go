// Copyright © 2026 Hanzo AI. MIT License.

// cors.go is the gateway's credentialed-CORS policy, stated ONCE.
//
// Which Origin may be reflected into Access-Control-Allow-Origin next to
// Access-Control-Allow-Credentials is a property of the REQUEST, not of the
// framework carrying it — the same decomplection [authGate] already made for
// authn. It lived inside a gin closure, and the cost of that braiding was the
// familiar one: the zip edge could not run the rule, so the HIP-0106 mount
// answered no preflight at all. A browser SPA talking to the unified binary got
// whatever the router does with an unrouted OPTIONS where the legacy edge
// answers 204 with the allowlist applied.
//
// Now the rule is a value — [corsPolicy] — and each transport is a few lines of
// adapter over it:
//
//	legacy_transports.go   gin, for the Lura edge (the shipping image)
//	mount.go               native zip, for the HIP-0106 unified cloud binary
//
// The header NAMES and VALUES live here too, in [corsAnswer], so the two edges
// cannot answer one preflight two ways.
package gateway

import (
	"os"
	"strings"
)

// corsPolicy is the credentialed-CORS decision, compiled once from the
// environment. Build it with [newCORSPolicy] and ask it per request.
type corsPolicy struct{ allowed func(origin string) bool }

// newCORSPolicy compiles the allowlist. It reads the environment once, at
// construction, exactly as the middleware it replaced did.
func newCORSPolicy() corsPolicy { return corsPolicy{allowed: newCORSOriginAllower()} }

// admit reports the CORS an Origin has earned. nil means NONE, and none is the
// safe answer: a request whose Origin is absent or not allowlisted gets no
// Access-Control-* header whatsoever, so no other site can make a credentialed
// cross-origin read against a session (Great-Audit F3).
func (p corsPolicy) admit(origin string) *corsAnswer {
	if origin == "" || !p.allowed(origin) {
		return nil
	}
	return &corsAnswer{origin: origin}
}

// corsAnswer is what an allowlisted Origin earns. It writes through a
// transport's own two-string header setter — gin's Header, zip's SetHeader — so
// the header names and values are stated once and neither edge can drift.
type corsAnswer struct{ origin string }

// credentials is what EVERY response to an allowlisted Origin carries: the
// reflection, the credentials flag, and Vary so a shared cache never serves one
// origin's Access-Control-Allow-Origin to another.
//
// It is the WHOLE of the panic-recovery path's CORS: a 500 is still an
// origin-dependent response and must not widen the policy into a
// wildcard-reflect-with-credentials primitive on the error path.
func (a *corsAnswer) credentials(set func(name, value string)) {
	set("Access-Control-Allow-Origin", a.origin)
	set("Access-Control-Allow-Credentials", "true")
	set("Vary", "Origin")
}

// negotiation is the rest of what a browser needs to complete a preflight. It
// is separate from [corsAnswer.credentials] because the error path deliberately
// sends only the credentials half — describing what a 500 may be read by, not
// what the API accepts.
func (a *corsAnswer) negotiation(set func(name, value string)) {
	set("Access-Control-Allow-Headers", corsAllowHeaders)
	set("Access-Control-Allow-Methods", corsAllowMethods)
	set("Access-Control-Max-Age", corsMaxAge)
}

const (
	corsAllowHeaders = "Content-Type, Authorization, X-User-Id, X-Org-Id, X-Project-Id, X-Environment, X-Roles, X-User-Email, X-Request-ID, X-Client-ID, X-Requested-With, Accept, Accept-Language"
	corsAllowMethods = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	corsMaxAge       = "86400"
)

// newCORSOriginAllower builds the gateway's single credentialed-CORS origin
// predicate. An origin is allowlisted iff it EITHER exact-matches a dev/env
// origin (the baked-in localhost defaults plus any fully-qualified
// scheme+host[:port] supplied via GATEWAY_CORS_ORIGINS, comma-separated) OR its
// hostname suffix-matches a baked-in brand domain (defaultAllowedOrigins — the
// SAME set the widget gate uses — including subdomains, so a browser SPA like
// https://cowork.hanzo.ai is allowed with no per-origin env).
//
// This is the ONE definition of the allowlist (DRY). Every site that reflects an
// Origin with credentials gates on it: the preflight transport on both edges AND
// the legacy engine's panic-recovery handler.
func newCORSOriginAllower() func(origin string) bool {
	origins := map[string]bool{
		"http://localhost:3000": true, "http://localhost:3001": true, "http://localhost:3100": true,
		"http://localhost:5173": true, "http://localhost:8080": true, "http://127.0.0.1:3000": true,
	}
	if extra := os.Getenv("GATEWAY_CORS_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins[o] = true
			}
		}
	}
	brandOrigins := widgetAllowedOrigins(defaultAllowedOrigins())
	return func(origin string) bool {
		if origins[origin] {
			return true
		}
		return isAllowedOrigin(extractOriginHost(origin), brandOrigins)
	}
}
