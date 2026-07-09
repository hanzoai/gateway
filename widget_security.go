package gateway

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

// NewWidgetSecurityMiddleware creates a gin middleware that enforces:
//
//  1. Per-IP rate limiting for widget keys (hz_*): prevents any single IP
//     from abusing the free widget endpoint.
//
//  2. Global rate limiting across all widget requests: prevents distributed
//     attacks from exhausting model API budget.
//
//  3. Origin validation: widget keys are only accepted from approved Hanzo
//     domains (Origin or Referer header). Non-browser clients (curl, scripts)
//     that omit Origin headers are rejected for widget keys.
//
// This middleware MUST run after NewAuthMiddleware. It only acts on requests
// with hz_ bearer tokens; all other requests pass through untouched.
func NewWidgetSecurityMiddleware(cfg WidgetSecurityConfig) gin.HandlerFunc {
	limiter := newWidgetRateLimiter(cfg)
	allowedOrigins := widgetAllowedOrigins(cfg.AllowedOrigins)

	return func(c *gin.Context) {
		token := extractBearerToken(c.Request)
		if !isWidgetKey(token) {
			c.Next()
			return
		}

		// --- Origin validation ---
		// Widget keys are public credentials embedded in client-side JS.
		// We restrict them to approved origins to limit abuse surface.
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			origin = c.Request.Header.Get("Referer")
		}
		originHost := extractOriginHost(origin)

		if len(allowedOrigins) > 0 {
			if originHost == "" {
				// No Origin/Referer: only allow if it looks like a health
				// check or internal request (User-Agent heuristic)
				ua := c.Request.Header.Get("User-Agent")
				isInternal := strings.Contains(ua, "kube-probe") ||
					strings.Contains(ua, "Wget") ||
					strings.Contains(ua, "curl") && c.ClientIP() == "127.0.0.1"
				if !isInternal {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":   "forbidden",
						"message": "Widget keys require an Origin header. Use a Hanzo API key (hk-*) for server-to-server requests.",
					})
					return
				}
			} else if !isAllowedOrigin(originHost, allowedOrigins) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "Widget key not authorized for origin: " + originHost,
				})
				return
			}
		}

		// --- Per-IP rate limiting ---
		clientIP := c.ClientIP()
		if !limiter.allow(clientIP) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limited",
				"message": "Widget rate limit exceeded. Try again shortly, or use a Hanzo API key (hk-*) for higher limits.",
			})
			return
		}

		c.Next()
	}
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
