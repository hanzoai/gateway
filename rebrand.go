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
// reassigned at runtime; it is stripped and replaced by the BrandingMiddleware
// below. Everything else is a package-level var and is reassigned in init().
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

// BrandingMiddleware strips any residual lura-emitted branding headers that
// leak through because their names are compile-time consts in lura/core, and
// replaces them with canonical Hanzo equivalents. Must run before the lura
// endpoint handler so the wrapped writer is in place by the time lura calls
// c.Header().
func BrandingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer = &brandingWriter{ResponseWriter: c.Writer}
		c.Next()
	}
}

// brandingWriter wraps gin.ResponseWriter and rewrites branding headers at
// the last possible moment (WriteHeaderNow / Write / WriteString) before the
// response goes to the wire.
type brandingWriter struct {
	gin.ResponseWriter
	rewritten bool
}

func (w *brandingWriter) rewrite() {
	if w.rewritten {
		return
	}
	w.rewritten = true
	h := w.ResponseWriter.Header()
	if v := h.Get(legacyBrandHeader); v != "" {
		h.Del(legacyBrandHeader)
		h.Set(PoweredByHeader, v)
	} else if h.Get(PoweredByHeader) == "" {
		h.Set(PoweredByHeader, fmt.Sprintf("%s Version %s", BrandName, core.KrakendVersion))
	}
	// Defense in depth: if lura's var reassignment races with a hot path, strip
	// the legacy completion header too.
	if v := h.Get(legacyCompletedHeader); v != "" {
		h.Del(legacyCompletedHeader)
		if h.Get(CompletedHeader) == "" {
			h.Set(CompletedHeader, v)
		}
	}
}

func (w *brandingWriter) WriteHeader(status int) {
	w.rewrite()
	w.ResponseWriter.WriteHeader(status)
}

func (w *brandingWriter) WriteHeaderNow() {
	w.rewrite()
	w.ResponseWriter.WriteHeaderNow()
}

func (w *brandingWriter) Write(p []byte) (int, error) {
	w.rewrite()
	return w.ResponseWriter.Write(p)
}

func (w *brandingWriter) WriteString(s string) (int, error) {
	w.rewrite()
	return w.ResponseWriter.WriteString(s)
}

// Ensure interface compliance.
var _ gin.ResponseWriter = (*brandingWriter)(nil)
var _ http.ResponseWriter = (*brandingWriter)(nil)
