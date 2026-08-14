// Copyright © 2026 Hanzo AI. MIT License.

// widget_security.go is the widget-key gate: what a PUBLIC credential embedded
// in client-side JavaScript is allowed to do.
//
// The gate is a value ([widgetGate]) for the same reason [authGate] is: the
// decision is about the request — its bearer token, its Origin, its client IP —
// and the gateway has two HTTP edges. While it was written inside a gin closure
// the zip edge could not run it, so the HIP-0106 mount enforced neither the
// origin allowlist nor the rate limit: an hz_ key stolen out of any page's
// source worked from anywhere, at any rate, against the model budget.
//
//	legacy_transports.go   gin, for the Lura edge (the shipping image)
//	mount.go               native zip, for the HIP-0106 unified cloud binary
package gateway

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/authz/edge"
)

// WidgetSecurityConfig holds configuration for widget key rate limiting
// and origin validation.
type WidgetSecurityConfig struct {
	// MaxRequestsPerIP is the maximum number of widget requests per IP
	// within the rate limit window. Default: 10.
	MaxRequestsPerIP int

	// Window is the sliding window duration for per-IP rate limiting.
	// Default: 1 minute.
	Window time.Duration

	// GlobalMaxRequests is the maximum total widget requests across all
	// IPs within the window. Protects against distributed abuse.
	// Default: 600.
	GlobalMaxRequests int

	// AllowedOrigins is the set of origin domains allowed for widget
	// requests. If empty, origin checking is disabled.
	AllowedOrigins []string

	// CleanupInterval controls how often stale entries are evicted
	// from the per-IP rate limit map. Default: 5 minutes.
	CleanupInterval time.Duration
}

// DefaultWidgetSecurityConfig returns safe defaults.
//
// AllowedOrigins can be overridden via WIDGET_ALLOWED_ORIGINS env var
// (comma-separated list of bare hostnames, no scheme/port). Subdomain
// matches are automatic: "hanzo.ai" also allows "*.hanzo.ai".
func DefaultWidgetSecurityConfig() WidgetSecurityConfig {
	origins := defaultAllowedOrigins()
	if env := os.Getenv("WIDGET_ALLOWED_ORIGINS"); env != "" {
		origins = nil
		for _, o := range strings.Split(env, ",") {
			if o = strings.TrimSpace(o); o != "" {
				origins = append(origins, o)
			}
		}
	}
	return WidgetSecurityConfig{
		MaxRequestsPerIP:  10,
		Window:            1 * time.Minute,
		GlobalMaxRequests: 600,
		AllowedOrigins:    origins,
		CleanupInterval:   5 * time.Minute,
	}
}

// defaultAllowedOrigins is the baked-in allowlist — covers every Hanzo/Lux/Zoo
// property that embeds the public widget key. Subdomains are matched by suffix.
func defaultAllowedOrigins() []string {
	return []string{
		// Hanzo
		"hanzo.ai",
		"hanzo.app",
		"hanzo.chat",
		"hanzo.bot",
		"hanzo.id",
		// Lux Network + subdomains
		"lux.network",
		"lux.financial",
		"lux.finance",
		"lux.market",
		"lux.industries",
		"lux.exchange",
		"lux.blog",
		"lux.chat",
		"lux.id",
		// Zoo
		"zoo.ngo",
		"zoo.network",
		"zoo.id",
		// Pars
		"pars.network",
		"pars.id",
		// Karma (external customer) — apex covers every subdomain (e.g.
		// tryon.karma.style) via the suffix match in isAllowedOrigin.
		"karma.style",
		// Local dev
		"localhost",
	}
}

// ipWindow tracks request timestamps for a single IP.
type ipWindow struct {
	timestamps []time.Time
}

// count returns how many requests are within the window.
func (w *ipWindow) count(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	// Trim expired entries from the front
	start := 0
	for start < len(w.timestamps) && w.timestamps[start].Before(cutoff) {
		start++
	}
	if start > 0 {
		w.timestamps = w.timestamps[start:]
	}
	return len(w.timestamps)
}

// add records a new request timestamp.
func (w *ipWindow) add(now time.Time) {
	w.timestamps = append(w.timestamps, now)
}

// widgetRateLimiter implements per-IP and global sliding window rate limiting
// for widget key requests.
type widgetRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*ipWindow // keyed by client IP
	global  ipWindow
	cfg     WidgetSecurityConfig
}

func newWidgetRateLimiter(cfg WidgetSecurityConfig) *widgetRateLimiter {
	rl := &widgetRateLimiter{
		windows: make(map[string]*ipWindow),
		cfg:     cfg,
	}
	// Start background cleanup goroutine
	go rl.cleanup()
	return rl
}

// allow checks both per-IP and global limits. Returns true if the request
// should be allowed.
func (rl *widgetRateLimiter) allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Check global limit first
	globalCount := rl.global.count(now, rl.cfg.Window)
	if globalCount >= rl.cfg.GlobalMaxRequests {
		return false
	}

	// Check per-IP limit
	w, ok := rl.windows[clientIP]
	if !ok {
		w = &ipWindow{}
		rl.windows[clientIP] = w
	}
	ipCount := w.count(now, rl.cfg.Window)
	if ipCount >= rl.cfg.MaxRequestsPerIP {
		return false
	}

	// Record the request
	w.add(now)
	rl.global.add(now)
	return true
}

// cleanup periodically evicts stale entries from the map.
func (rl *widgetRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cfg.CleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, w := range rl.windows {
			w.count(now, rl.cfg.Window) // trims expired entries
			if len(w.timestamps) == 0 {
				delete(rl.windows, ip)
			}
		}
		rl.global.count(now, rl.cfg.Window) // trim global too
		rl.mu.Unlock()
	}
}

// isWidgetKey returns true for Hanzo widget key tokens (hz_ prefix).
func isWidgetKey(token string) bool {
	return strings.HasPrefix(token, "hz_")
}

// widgetAllowedOrigins builds a set from the config slice for O(1) lookup.
func widgetAllowedOrigins(origins []string) map[string]bool {
	m := make(map[string]bool, len(origins))
	for _, o := range origins {
		m[o] = true
	}
	return m
}

// extractOriginHost extracts the hostname from an Origin or Referer header.
// Returns empty string if not parseable.
func extractOriginHost(origin string) string {
	if origin == "" {
		return ""
	}
	// Strip scheme (http:// or https://)
	if idx := strings.Index(origin, "://"); idx >= 0 {
		origin = origin[idx+3:]
	}
	// Strip path
	if idx := strings.IndexByte(origin, '/'); idx >= 0 {
		origin = origin[:idx]
	}
	// Strip port
	host, _, err := net.SplitHostPort(origin)
	if err != nil {
		// No port, origin is the host
		return origin
	}
	return host
}

// widgetGate is the compiled widget-key policy: the origin allowlist and the
// sliding-window limiter, built once from a [WidgetSecurityConfig] and asked per
// request. Build it with [newWidgetGate].
type widgetGate struct {
	limiter *widgetRateLimiter
	allowed map[string]bool
	peers   peerPolicy
}

// newWidgetGate compiles cfg. The limiter's background eviction goroutine starts
// here, so build one gate per transport and reuse it — not one per request.
func newWidgetGate(cfg WidgetSecurityConfig) *widgetGate {
	return &widgetGate{
		limiter: newWidgetRateLimiter(cfg),
		allowed: widgetAllowedOrigins(cfg.AllowedOrigins),
		peers:   newPeerPolicy(),
	}
}

// admit enforces, for hz_ widget keys only:
//
//  1. Origin validation: a widget key is accepted only from an approved domain
//     (Origin, else Referer). Clients that send neither are refused, because a
//     public credential outside a browser is a credential in a script.
//
//  2. Per-IP rate limiting: no single client may drain the free widget endpoint.
//
//  3. Global rate limiting: no distributed set of clients may drain the model
//     budget.
//
// WHAT EACH ONE IS WORTH, stated because the order matters. Origin is written by
// whoever makes the request: against a BROWSER it is trustworthy — the browser
// sets it and a page cannot lie about its own origin — and that is the abuse this
// list is for. Against a script it is not a control at all, and no allowlist can
// make it one. So (2) and (3) are the only limits that bind a scripted attacker
// holding a key lifted from a page's source, which is why the key they bucket on
// is a policy decision (peerPolicy) and not a framework helper.
//
// It runs AFTER [authGate.admit] on both edges, and it only ever REFUSES — it
// writes no identity and mints nothing, so the trust boundary is unaffected by
// where it sits. Every request not carrying a widget key passes through untouched.
//
// h is read-only. peer is the transport's view of the SOCKET peer; the address
// actually bucketed is [peerPolicy.clientIP] of it and the forwarded chain, so
// both edges bucket one request one way.
//
// Returns nil to allow. A non-nil *refusal is the status and JSON body to answer
// with — the same currency [authGate.admit] deals in, so a transport handles one
// refusal shape and not two.
func (g *widgetGate) admit(h edge.Headers, peer string) *refusal {
	if !isWidgetKey(edge.Bearer(h)) {
		return nil
	}

	// --- Origin validation ---
	// Widget keys are public credentials embedded in client-side JS.
	// We restrict them to approved origins to limit browser-driven abuse.
	origin := h.Get("Origin")
	if origin == "" {
		origin = h.Get("Referer")
	}
	originHost := extractOriginHost(origin)

	if len(g.allowed) > 0 {
		if originHost == "" {
			// No Origin and no Referer. There is no exception here: the gate
			// used to admit anything whose User-Agent said "kube-probe" or
			// "Wget", which is a bypass with a published recipe — a User-Agent
			// is written by the caller. Nothing legitimate needed it either, as
			// a kubelet probe sends no Authorization header and so never reaches
			// this branch at all.
			return &refusal{Status: http.StatusForbidden, Body: map[string]string{
				"error":   "forbidden",
				"message": "Widget keys require an Origin header. Use a Hanzo API key (sk-*) for server-to-server requests.",
			}}
		} else if !isAllowedOrigin(originHost, g.allowed) {
			return &refusal{Status: http.StatusForbidden, Body: map[string]string{
				"error":   "forbidden",
				"message": "Widget key not authorized for origin: " + originHost,
			}}
		}
	}

	// --- Per-IP rate limiting ---
	if !g.limiter.allow(g.peers.clientIP(peer, h.Get("X-Forwarded-For"))) {
		return &refusal{Status: http.StatusTooManyRequests, Body: map[string]string{
			"error":   "rate_limited",
			"message": "Widget rate limit exceeded. Try again shortly, or use a Hanzo API key (sk-*) for higher limits.",
		}}
	}

	return nil
}

// isAllowedOrigin checks if the origin host matches any allowed origin,
// including subdomain matching (e.g., "foo.hanzo.ai" matches "hanzo.ai").
func isAllowedOrigin(host string, allowed map[string]bool) bool {
	// Exact match
	if allowed[host] {
		return true
	}
	// Subdomain match: check if host ends with "."+allowed
	for origin := range allowed {
		if strings.HasSuffix(host, "."+origin) {
			return true
		}
	}
	return false
}
