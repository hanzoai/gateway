//go:build legacy
// +build legacy

// Package gateway rebrands every user-visible Lura/KrakenD identifier so that
// nothing a client or backend sees contains the string "krakend" or "KrakenD".
//
// Lura (the upstream SDK we build on) emits several hard-coded brand strings:
//   - response header "X-KRAKEND"
//   - response header "X-Krakend-Completed"
//   - outbound backend User-Agent "KrakenD Version x.y"
//   - core.KrakendHeaderValue "Version x.y"
//
// The response header name "X-KRAKEND" is a const in lura/core and cannot be
// reassigned at runtime; it is stripped by the ProductionHeadersMiddleware
// below (which also stamps the production posture). Everything else is a
// package-level var and is reassigned in init().
package gateway

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/core"
	"github.com/luraproject/lura/v2/transport/http/server"
)

// BrandName is the canonical rebrand string emitted on responses and outbound
// backend calls. Overridable at build time via:
//
//	-ldflags "-X github.com/hanzoai/gateway.BrandName=..."
var BrandName = "hanzoai/gateway"

// PoweredByHeader is the user-visible response header that replaces "X-KRAKEND".
const PoweredByHeader = "X-Powered-By"

// CompletedHeader is the user-visible response header that replaces
// "X-Krakend-Completed". It keeps the same "true" / "false" semantic so any
// client depending on the completion flag only needs to change the header key.
const CompletedHeader = "X-Gateway-Completed"

// legacyCompletedHeader is the hard-coded lura header name we need to strip.
const legacyCompletedHeader = "X-Krakend-Completed"

// legacyBrandHeader is the hard-coded lura header name (const in lura/core).
const legacyBrandHeader = "X-KRAKEND"

func init() {
	// Reassign package-level vars in lura so that anything lura emits at runtime
	// carries the Hanzo brand instead. core.KrakendVersion is set via ldflags in
	// the Makefile; we pick up whatever value it holds at init time.
	brandValue := fmt.Sprintf("%s Version %s", BrandName, core.KrakendVersion)
	core.KrakendHeaderValue = brandValue
	core.KrakendUserAgent = brandValue
	server.UserAgentHeaderValue = []string{brandValue}
	server.CompleteResponseHeaderName = CompletedHeader
}

// ProductionHeadersMiddleware stamps the production response-header posture and
// strips every upstream-SDK branding header, on every response — happy path,
// error paths, and NoRoute / NoMethod alike. It wraps the gin ResponseWriter so
// the headers are set at the last possible moment, before the response reaches
// the wire.
//
// This is the legacy (gin/KrakenD) edge's home for the same posture zip's
// middleware.ProductionHeaders gives the ZAP-native services: Server is the
// white-label brand of the request Host (never the framework name, never a
// single hardcoded brand), X-Api-Version is the brand-neutral build version, and
// HSTS + nosniff are the security floor. It never emits X-Powered-By or any
// framework/version string.
//
// Must run right after recovery so the wrapped writer is in place for every
// downstream handler.
func ProductionHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer = &prodWriter{ResponseWriter: c.Writer, host: c.Request.Host}
		c.Next()
	}
}

// prodWriter wraps gin.ResponseWriter and stamps the production posture (and
// strips upstream branding) at the last possible moment — WriteHeader /
// WriteHeaderNow / Write / WriteString — before the response goes to the wire.
type prodWriter struct {
	gin.ResponseWriter
	host    string
	stamped bool
}

func (w *prodWriter) stamp() {
	if w.stamped {
		return
	}
	w.stamped = true
	h := w.ResponseWriter.Header()

	// Strip every framework-leaking header. X-KRAKEND is a compile-time const in
	// lura/core (cannot be reassigned), so it is deleted here; X-Powered-By is
	// never emitted (the standard forbids it) and is stripped defensively; the
	// completion flag keeps its brand-neutral semantic under a de-branded name.
	h.Del(legacyBrandHeader) // X-KRAKEND
	h.Del(PoweredByHeader)   // X-Powered-By
	if v := h.Get(legacyCompletedHeader); v != "" {
		h.Del(legacyCompletedHeader)
		if h.Get(CompletedHeader) == "" {
			h.Set(CompletedHeader, v)
		}
	}

	// Production posture (Stripe/Cloudflare/GitHub-grade):
	//  - Server: white-label brand of the request Host, else the neutral default.
	server := brandForHost(w.host)
	if server == "" {
		server = NeutralServerBrand
	}
	h.Set("Server", server)
	//  - X-Api-Version: brand-neutral build/version signal for support correlation.
	if core.KrakendVersion != "" {
		h.Set("X-Api-Version", core.KrakendVersion)
	}
	//  - Security floor (always-safe; the SPA owns its own framing rules).
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Strict-Transport-Security", hstsPolicy)
}

func (w *prodWriter) WriteHeader(status int) {
	w.stamp()
	w.ResponseWriter.WriteHeader(status)
}

func (w *prodWriter) WriteHeaderNow() {
	w.stamp()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *prodWriter) Write(p []byte) (int, error) {
	w.stamp()
	return w.ResponseWriter.Write(p)
}

func (w *prodWriter) WriteString(s string) (int, error) {
	w.stamp()
	return w.ResponseWriter.WriteString(s)
}

// Flush covers the streaming/SSE path: a handler that Flushes before any
// buffered write would otherwise reach the embedded writer's WriteHeaderNow
// directly (Go embedding has no virtual dispatch), bypassing stamp(). Stamp
// first so streamed responses carry the posture and shed the framework headers
// too. (A hijacked connection — 101 websocket upgrade — carries no HTTP response
// posture and is intentionally left unstamped.)
func (w *prodWriter) Flush() {
	w.stamp()
	w.ResponseWriter.Flush()
}

// Ensure interface compliance.
var _ gin.ResponseWriter = (*prodWriter)(nil)
var _ http.ResponseWriter = (*prodWriter)(nil)
