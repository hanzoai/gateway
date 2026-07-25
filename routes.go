// Copyright © 2026 Hanzo AI. MIT License.

// routes.go is the gateway's pure host/path reverse-proxy routing table and
// CORS preflight — stdlib + gin + yaml, with ZERO dependency on the upstream
// Lura SDK. It is the default-build routing surface: the HIP-0110
// trust-boundary mount (mount.go) loads this table via LoadRoutesFromFile so
// any path not owned by a co-resident subsystem is proxied to its configured
// backend, and the standalone binary shares the same table.
//
// The legacy Lura gin-engine builder (NewEngine) that also consumed
// this table used to live alongside it in router_engine.go; it now sits behind
// the `legacy` build tag in legacy_engine.go so the upstream Lura graph
// stays out of the default build and the shipping image (see that file's
// header for the full rationale).
package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// RoutesConfig is the YAML structure for gateway routing.
// Loaded from KMS (GATEWAY_ROUTES_KMS_PATH) or local file (GATEWAY_ROUTES_FILE).
type RoutesConfig struct {
	Redirects  map[string]string       `yaml:"redirects" json:"redirects"`
	Routes     map[string][]RouteEntry `yaml:"routes" json:"routes"`
	Subdomains map[string]string       `yaml:"subdomains" json:"subdomains"`
}

// RouteEntry maps a path prefix to a backend URL.
type RouteEntry struct {
	Prefix  string `yaml:"prefix" json:"prefix"`
	Backend string `yaml:"backend" json:"backend"`
	Rewrite string `yaml:"rewrite,omitempty" json:"rewrite,omitempty"` // optional: rewrite prefix
}

// pathBackend maps a path prefix to a backend URL.
type pathBackend struct {
	prefix string
	target *url.URL
}

// compiledRoute is a pre-built proxy for a path prefix.
type compiledRoute struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

// routeTable holds the compiled routing state. Thread-safe for hot-reload.
type routeTable struct {
	mu          sync.RWMutex
	exactRoutes map[string][]compiledRoute
	redirects   map[string]string
	subProxies  []struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
}

var routes = &routeTable{}

// LoadRoutes loads routing config from YAML. Called at startup and on hot-reload.
func LoadRoutes(cfg *RoutesConfig) error {
	exact := make(map[string][]compiledRoute, len(cfg.Routes))

	for host, entries := range cfg.Routes {
		// Sort by longest prefix first.
		sorted := make([]RouteEntry, len(entries))
		copy(sorted, entries)
		sort.Slice(sorted, func(i, j int) bool {
			return len(sorted[i].Prefix) > len(sorted[j].Prefix)
		})

		compiled := make([]compiledRoute, 0, len(sorted))
		for _, e := range sorted {
			u, err := url.Parse(e.Backend)
			if err != nil {
				return fmt.Errorf("bad backend URL %q for %s%s: %w", e.Backend, host, e.Prefix, err)
			}
			var p *httputil.ReverseProxy
			if e.Rewrite != "" {
				p = newRewriteProxy(u, e.Prefix, e.Rewrite)
			} else {
				p = newProxy(u)
			}
			compiled = append(compiled, compiledRoute{prefix: e.Prefix, proxy: p})
		}
		exact[host] = compiled
	}

	type subProxy struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
	var subs []struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
	for pattern, target := range cfg.Subdomains {
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("bad subdomain backend %q for %s: %w", target, pattern, err)
		}
		subs = append(subs, struct {
			pattern string
			proxy   *httputil.ReverseProxy
		}{pattern: pattern, proxy: newProxy(u)})
	}

	routes.mu.Lock()
	routes.exactRoutes = exact
	routes.redirects = cfg.Redirects
	routes.subProxies = subs
	routes.mu.Unlock()

	return nil
}

// LoadRoutesFromFile loads routes from a YAML file.
func LoadRoutesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read routes file %s: %w", path, err)
	}
	return loadRoutesFromYAML(data)
}

// loadRoutesFromYAML parses a YAML payload and installs the routes table.
// Shared by LoadRoutesFromFile and the KMS code path so both go through one
// validation/parse step.
func loadRoutesFromYAML(data []byte) error {
	var cfg RoutesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse routes yaml: %w", err)
	}
	return LoadRoutes(&cfg)
}

// loadRoutesFromEnv loads routes from KMS path or local file.
// Priority: GATEWAY_ROUTES_KMS_PATH > GATEWAY_ROUTES_FILE > ./routes.yaml
//
// KMS path is delegated to the package-level kmsResolver. When
// GATEWAY_KMS_ENDPOINT is set (plus IAM_CLIENT_ID/SECRET), the HTTP resolver
// is wired automatically. Tests inject a stub via SetKMSResolver.
func loadRoutesFromEnv() error {
	initKMSResolverFromEnv()

	if kmsPath := os.Getenv("GATEWAY_ROUTES_KMS_PATH"); kmsPath != "" {
		data, err := kmsResolver.FetchRoutes(kmsPath)
		if err != nil {
			return fmt.Errorf("failed to fetch routes from KMS path %s: %w", kmsPath, err)
		}
		if err := loadRoutesFromYAML(data); err != nil {
			return fmt.Errorf("kms routes payload invalid: %w", err)
		}
		return nil
	}

	filePath := os.Getenv("GATEWAY_ROUTES_FILE")
	if filePath == "" {
		filePath = "routes.yaml"
	}
	return LoadRoutesFromFile(filePath)
}

// newProxy creates an httputil.ReverseProxy that preserves the original
// Host header and strips backend CORS headers (gateway handles CORS).
func newProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// stripBackendCORS removes CORS headers from backend responses.
// The gateway middleware is the single source of CORS headers.
func stripBackendCORS(resp *http.Response) error {
	resp.Header.Del("Access-Control-Allow-Origin")
	resp.Header.Del("Access-Control-Allow-Methods")
	resp.Header.Del("Access-Control-Allow-Headers")
	resp.Header.Del("Access-Control-Allow-Credentials")
	resp.Header.Del("Access-Control-Max-Age")
	resp.Header.Del("Access-Control-Expose-Headers")
	return nil
}

// newPassthroughProxy creates an httputil.ReverseProxy that forwards the
// request path unchanged to the target host.
func newPassthroughProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// newRewriteProxy creates an httputil.ReverseProxy that rewrites path prefixes.
func newRewriteProxy(target *url.URL, oldPrefix, newPrefix string) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		if strings.HasPrefix(req.URL.Path, oldPrefix) {
			req.URL.Path = newPrefix + req.URL.Path[len(oldPrefix):]
		}
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// defaultCloudAPIURL is the in-cluster cloud (HIP-0106 cloud binary)
// HTTP endpoint that serves /v1/* models traffic natively.
const defaultCloudAPIURL = "http://cloud.hanzo.svc.cluster.local:8000"

// cloudAPIURL resolves the cloud HTTP target. Overridable via
// GATEWAY_CLOUD_API_URL for operators (alternate service DNS) and tests
// (httptest backend). Falls back to defaultCloudAPIURL when unset or
// unparseable so a malformed override can never silently break routing.
func cloudAPIURL() *url.URL {
	raw := strings.TrimSpace(os.Getenv("GATEWAY_CLOUD_API_URL"))
	if raw == "" {
		raw = defaultCloudAPIURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, _ = url.Parse(defaultCloudAPIURL)
	}
	return u
}

// apiCloudHosts is the host whose ENTIRE surface is the unified cloud API.
// ONE API host — api.hanzo.ai (no .cloud.). It resolves to the hanzoai/cloud
// binary (HIP-0106), which owns ALL /v1/* routing — AI inference top-level
// (/v1/chat, /v1/messages, …) plus every per-service control plane (/v1/cloud,
// /v1/iam, /v1/kms, /v1/o11y, …). The gateway is a STATELESS edge: auth +
// ratelimit + meter already ran in the upstream middleware, so it forwards "/*"
// straight to cloud with NO per-route allow-list. ONE routing source of truth =
// cloud's mount table, not a second map here.
var apiCloudHosts = map[string]bool{
	"api.hanzo.ai": true,
	// api.cloud.hanzo.ai is the upstream Host the ingress `console-v1-host` (and
	// `cloud-api-host`) middlewares rewrite console.hanzo.ai/v1/* and
	// cloud-api.hanzo.ai/v1/* to before this gateway. Without it here those hosts
	// fell through to the per-service exactRoutes (which carry /v1/billing,
	// /v1/commerce, … but NOT the visor control plane), so /v1/gpus, /v1/machines,
	// /v1/clusters, /v1/fleet 404'd — breaking the console GPUs + Machines pages for
	// EVERY customer. Treating it as a unified-cloud-API host forwards the WHOLE /v1
	// surface to cloud (which owns visor + all control-plane routing), exactly like
	// api.hanzo.ai. SECURITY unchanged: NewAuthMiddleware runs BEFORE the host
	// passthrough for ALL hosts — it unconditionally strips client identity headers
	// and re-mints X-Org-Id from the validated JWT — so this carries a gateway-
	// sanitized request, never a client-trusted X-Org-Id.
	"api.cloud.hanzo.ai": true,
}

// hostProxyMiddleware intercepts requests and routes them to the correct
// backend based on hostname and path prefix. Supports WebSocket upgrades
// natively via httputil.ReverseProxy.
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

// newCORSOriginAllower builds the gateway's single credentialed-CORS origin
// predicate. An origin may be reflected into Access-Control-Allow-Origin
// alongside Access-Control-Allow-Credentials:true iff it EITHER exact-matches a
// dev/env origin (the baked-in localhost defaults plus any fully-qualified
// scheme+host[:port] supplied via GATEWAY_CORS_ORIGINS, comma-separated) OR its
// hostname suffix-matches a baked-in brand domain (defaultAllowedOrigins — the
// SAME set the widget security middleware uses — including subdomains, so a
// browser SPA like https://cowork.hanzo.ai is allowed with no per-origin env).
//
// This is the ONE definition of the credentialed-CORS allowlist (DRY). Every
// site that reflects an Origin with credentials MUST gate on this predicate:
// the preflight middleware (corsPreflightMiddleware) AND the legacy engine's
// panic-recovery handler (corsRecoveryHandler in legacy_engine.go). That
// invariant is what stops a 5xx error path from widening the policy into a
// wildcard-reflect-with-credentials primitive (Great-Audit F3). The predicate
// reads the environment once at construction, mirroring the middleware.
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

// corsRecoveryHandler is the gateway's panic-recovery CORS shaper: a downstream
// panic returns a 500 (never a dropped connection / 502 at ingress) and — on
// the SAME allowlist as the happy path (originAllowed, from
// newCORSOriginAllower) — reflects the request Origin with
// Access-Control-Allow-Credentials ONLY for an allowlisted Origin. A
// non-allowlisted or absent Origin gets NO CORS headers, so a 5xx can never
// become a wildcard-reflect-with-credentials primitive that would let any site
// make credentialed cross-origin reads against a session on the error path
// (Great-Audit F3). Vary:Origin is set whenever the response is
// origin-dependent so shared caches never serve one origin's ACAO to another.
//
// It lives here beside corsPreflightMiddleware — routes.go owns the ONE CORS
// policy (default build) — and is wired by the legacy engine via
// gin.CustomRecovery (legacy_engine.go), the same way that engine consumes
// corsPreflightMiddleware / hostProxyMiddleware from this file.
func corsRecoveryHandler(originAllowed func(string) bool) gin.RecoveryFunc {
	return func(c *gin.Context, _ any) {
		if origin := c.GetHeader("Origin"); origin != "" && originAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Vary", "Origin")
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	}
}

// corsPreflightMiddleware handles OPTIONS preflight requests globally.
// Must run before any gateway routing to prevent 405/503 on preflight.
func corsPreflightMiddleware() gin.HandlerFunc {
	originAllowed := newCORSOriginAllower()
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" || !originAllowed(origin) {
			c.Next()
			return
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-Id, X-Org-Id, X-Project-Id, X-Environment, X-Roles, X-User-Email, X-Request-ID, X-Client-ID, X-Requested-With, Accept, Accept-Language")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		c.Writer.Header().Set("Vary", "Origin")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
