// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// legacy_transports.go carries every gin TRANSPORT the gateway has, and nothing
// else. Each one is a handful of lines that reads a *gin.Context, asks a policy
// value that knows about no framework, and writes gin's answer:
//
//	authGate.admit    authpolicy.go   → NewAuthMiddleware
//	widgetGate.admit  widget_security.go → NewWidgetSecurityMiddleware
//	corsPolicy.admit  cors.go         → corsPreflightMiddleware, corsRecoveryHandler
//	routeTable        routes.go       → hostProxyMiddleware
//
// It exists as ONE file behind ONE build tag because it has ONE reason to exist
// and ONE fate: gin lives in this repo solely to run the vendored KrakenD/Lura
// engine (internal/lura, internal/plugin), which is what the shipping
// `ghcr.io/hanzoai/gateway` image executes. When the unified cloud binary's
// gateway.Mount is the sole edge (HIP-0110 Phase C), this file is deleted with
// legacy_engine.go and its siblings, in one commit, and gin leaves go.mod with
// them.
//
// Until then the DEFAULT build — the package hanzoai/cloud embeds via
// gateway.Mount, and the binary cmd/gateway/main.go builds — carries no gin at
// all. Every policy above has a native zip transport in mount.go, and
// transport_parity_test.go drives one request through both and asserts they
// agree.
package gateway

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// NewAuthMiddleware is the gin transport of the authn policy: validate the IAM
// JWT, strip client-supplied identity, write what the token earned, gate the
// balance. The whole ladder is [authGate.admit]; this only carries gin's half of
// the conversation.
//
// Canonical identity headers (the only ones downstream services should rely on)
// and the trust boundary they sit behind are documented on [authGate.admit] and
// in identity.go. Nothing here decides anything.
func NewAuthMiddleware(cfg AuthConfig) gin.HandlerFunc {
	gate := newAuthGate(cfg)
	return func(c *gin.Context) {
		if r := gate.admit(c.Request.Method, c.Request.Host, c.Request.URL.Path,
			httpHeaders{c.Request.Header}); r != nil {
			c.AbortWithStatusJSON(r.Status, r.Body)
			return
		}
		c.Next()
	}
}

// NewWidgetSecurityMiddleware is the gin transport of the widget-key gate
// ([widgetGate.admit]): origin allowlist + per-IP and global rate limits for
// hz_ keys. It MUST run after NewAuthMiddleware; every non-widget request passes
// through untouched.
//
// It hands the gate RemoteIP — the socket peer — and NOT ClientIP. ClientIP
// applies gin's own forwarded-header policy, and gin's default trusted set is
// 0.0.0.0/0 (defaultTrustedCIDRs; this repo never calls SetTrustedProxies), so it
// returns the leftmost X-Forwarded-For entry: the value the client wrote. Bucketing
// a rate limit on that is not a rate limit. The gate applies clientip.go's policy
// to the peer and the chain instead, which is also what makes this transport and
// the zip one answer alike.
func NewWidgetSecurityMiddleware(cfg WidgetSecurityConfig) gin.HandlerFunc {
	gate := newWidgetGate(cfg)
	return func(c *gin.Context) {
		if r := gate.admit(c.Request.Header, c.RemoteIP()); r != nil {
			c.AbortWithStatusJSON(r.Status, r.Body)
			return
		}
		c.Next()
	}
}

// corsPreflightMiddleware is the gin transport of the CORS policy ([corsPolicy]).
// It must run before any gateway routing — gin's NoMethod handler answers
// 405/503 to an OPTIONS on a gateway-managed endpoint otherwise.
func corsPreflightMiddleware() gin.HandlerFunc {
	policy := newCORSPolicy()
	return func(c *gin.Context) {
		a := policy.admit(c.GetHeader("Origin"))
		if a == nil {
			c.Next()
			return
		}
		a.credentials(c.Writer.Header().Set)
		a.negotiation(c.Writer.Header().Set)
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// corsRecoveryHandler is the legacy engine's panic-recovery CORS shaper: a
// downstream panic returns a 500 (never a dropped connection / 502 at ingress)
// carrying the credentials half of the SAME allowlist the happy path uses, so a
// 5xx can never become a wildcard-reflect-with-credentials primitive
// (Great-Audit F3).
//
// It takes the predicate rather than building one so the engine can pass the
// very allower its preflight middleware uses, which is what makes "the same
// allowlist" checkable rather than asserted.
func corsRecoveryHandler(originAllowed func(string) bool) gin.RecoveryFunc {
	policy := corsPolicy{allowed: originAllowed}
	return func(c *gin.Context, _ any) {
		if a := policy.admit(c.GetHeader("Origin")); a != nil {
			a.credentials(c.Header)
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	}
}

// hostProxyMiddleware routes a request to its backend by hostname and path
// prefix, from the table routes.go compiled. WebSocket upgrades and streamed
// responses work because this runs on net/http, which is why the table has no
// zip transport — see the header of routes.go.
func hostProxyMiddleware() gin.HandlerFunc {
	// api.hanzo.ai routes /v1/* and /zap directly to cloud as-is.
	// Cloud-api speaks /v1/* natively (no /api/ prefix), so no path rewrite.
	// The target is overridable via GATEWAY_CLOUD_API_URL (operator/test) and
	// defaults to the in-cluster cloud service. This is the HTTP relay to
	// the real model backend (HIP-0106 cloud binary at :8000) — the proven
	// completions path; the ZAP relay (build_app.go) is optional and is only
	// needed when ingress speaks ZAP, never for HTTP serving.
	cloudAPITarget := cloudAPIURL()
	apiPassthroughProxy := newPassthroughProxy(cloudAPITarget)

	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]
		path := c.Request.URL.Path

		// CORS headers are set by corsPreflightMiddleware (runs before this).
		// No CORS handling needed here.

		routes.mu.RLock()
		redirects := routes.redirects
		exactRoutes := routes.exactRoutes
		subProxies := routes.subProxies
		routes.mu.RUnlock()

		// Host redirects (301 permanent).
		if target, ok := redirects[host]; ok {
			c.Redirect(301, target+path)
			c.Abort()
			return
		}

		// Unified cloud API hosts: forward EVERY path to cloud, unchanged
		// (cloud speaks /v1/* natively — no rewrite). Stateless passthrough; cloud
		// owns all routing.
		if apiCloudHosts[host] {
			apiPassthroughProxy.ServeHTTP(c.Writer, c.Request)
			c.Abort()
			return
		}

		// Exact host match.
		if compiled, ok := exactRoutes[host]; ok {
			for _, r := range compiled {
				if strings.HasPrefix(path, r.prefix) {
					r.proxy.ServeHTTP(c.Writer, c.Request)
					c.Abort()
					return
				}
			}
		}

		// Subdomain pattern match.
		for _, sp := range subProxies {
			if strings.Contains(host, sp.pattern) {
				sp.proxy.ServeHTTP(c.Writer, c.Request)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
