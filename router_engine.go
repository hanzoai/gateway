package gateway

import (
	"encoding/json"
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

	botdetector "github.com/krakend/krakend-botdetector/v2/gin"
	httpsecure "github.com/krakend/krakend-httpsecure/v2/gin"
	lua "github.com/krakend/krakend-lua/v2/router/gin"
	opencensus "github.com/krakend/krakend-opencensus/v2/router/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/core"
	luragin "github.com/luraproject/lura/v2/router/gin"
	"github.com/luraproject/lura/v2/transport/http/server"
)

// RoutesConfig is the YAML structure for gateway routing.
// Loaded from KMS (GATEWAY_ROUTES_KMS_PATH) or local file (GATEWAY_ROUTES_FILE).
type RoutesConfig struct {
	Redirects  map[string]string              `yaml:"redirects" json:"redirects"`
	Routes     map[string][]RouteEntry        `yaml:"routes" json:"routes"`
	Subdomains map[string]string              `yaml:"subdomains" json:"subdomains"`
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
	mu            sync.RWMutex
	exactRoutes   map[string][]compiledRoute
	redirects     map[string]string
	subProxies    []struct {
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

// defaultCloudAPIURL is the in-cluster cloud-api (HIP-0106 cloud binary)
// HTTP endpoint that serves /v1/* models traffic natively.
const defaultCloudAPIURL = "http://cloud-api.hanzo.svc.cluster.local:8000"

// cloudAPIURL resolves the cloud-api HTTP target. Overridable via
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

// apiHanzoAIEndpoints lists the /v1/* path prefixes that route directly
// to cloud-api, bypassing the gateway JWT middleware.
var apiHanzoAIEndpoints = []string{
	"/v1/chat",
	"/v1/completions",
	"/v1/messages",
	"/v1/models",
	"/v1/embeddings",
	"/v1/images",
	"/v1/audio",
	"/v1/zap",
	"/zap",
}

// hostProxyMiddleware intercepts requests and routes them to the correct
// backend based on hostname and path prefix. Supports WebSocket upgrades
// natively via httputil.ReverseProxy.
func hostProxyMiddleware() gin.HandlerFunc {
	// api.hanzo.ai routes /v1/* and /zap directly to cloud-api as-is.
	// Cloud-api speaks /v1/* natively (no /api/ prefix), so no path rewrite.
	// The target is overridable via GATEWAY_CLOUD_API_URL (operator/test) and
	// defaults to the in-cluster cloud-api service. This is the HTTP relay to
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

		// api.hanzo.ai: route AI endpoints directly to cloud-api (no rewrite).
		if host == "api.hanzo.ai" {
			for _, prefix := range apiHanzoAIEndpoints {
				if strings.HasPrefix(path, prefix) {
					apiPassthroughProxy.ServeHTTP(c.Writer, c.Request)
					c.Abort()
					return
				}
			}
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

// NewEngine creates a new gin engine with middlewares and routing.
func NewEngine(cfg config.ServiceConfig, opt luragin.EngineOptions) *gin.Engine {
	// Inject disable_health into the service config JSON so lura's NewEngine
	// Must modify the raw JSON bytes because lura parses ExtraConfig from JSON,
	// not from the map.
	if cfg.ExtraConfig == nil {
		cfg.ExtraConfig = map[string]interface{}{}
	}
	cfg.ExtraConfig[luragin.Namespace] = map[string]interface{}{
		"disable_health": true,
	}
	engine := luragin.NewEngine(cfg, opt)

	// Disable gin's case-insensitive path redirect — triggers a panic in gin 1.9.1
	// when routes have mixed static/param nodes (e.g., /v1/ats/assets/:id/quote).
	// See: https://github.com/gin-gonic/gin/issues/3348
	engine.RedirectFixedPath = false

	// Load routes from config (KMS or file).
	if err := loadRoutesFromEnv(); err != nil {
		opt.Logger.Warning("[SERVICE: Gateway] Failed to load routes:", err)
		opt.Logger.Warning("[SERVICE: Gateway] No host routing will be available")
	}

	// Register /healthz directly. Lura's built-in health is disabled
	// (disable_health: true) to avoid duplicate-route panics, so we must
	// provide the platform-standard health endpoint.
	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Panic recovery — must run FIRST so any downstream panic returns 500
	// with CORS headers instead of crashing the connection (502 at ingress).
	engine.Use(gin.CustomRecovery(func(c *gin.Context, recovered any) {
		// Ensure CORS headers so browser sees the error (not a CORS failure)
		if origin := c.GetHeader("Origin"); origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	}))

	// Branding: wrap the response writer so any residual upstream-SDK-emitted
	// "X-KRAKEND*" headers are rewritten to our Hanzo-branded equivalents
	// before the response reaches the client. Must run right after recovery
	// so the wrapped writer is in place for every downstream handler.
	engine.Use(BrandingMiddleware())

	// CORS preflight must run BEFORE any routing — Gin's NoMethod handler
	// returns 405/503 for OPTIONS on gateway-managed endpoints otherwise.
	engine.Use(corsPreflightMiddleware())
	engine.Use(NewAuthMiddleware(DefaultAuthConfig()))
	engine.Use(NewWidgetSecurityMiddleware(DefaultWidgetSecurityConfig()))
	engine.Use(hostProxyMiddleware())

	engine.NoRoute(func(c *gin.Context) {
		if c.IsAborted() {
			return
		}
		opencensus.HandlerFunc(&config.EndpointConfig{Endpoint: "NoRoute"}, defaultHandler, nil)(c)
	})
	engine.NoMethod(opencensus.HandlerFunc(&config.EndpointConfig{Endpoint: "NoMethod"}, defaultHandler, nil))

	if v, ok := cfg.ExtraConfig[luragin.Namespace]; ok && v != nil {
		var ginOpts ginOptions
		if b, err := json.Marshal(v); err == nil {
			json.Unmarshal(b, &ginOpts)
		}
		if ginOpts.ErrorBody.Err404 != nil {
			engine.NoRoute(func(c *gin.Context) {
				if c.IsAborted() {
					return
				}
				opencensus.HandlerFunc(&config.EndpointConfig{Endpoint: "NoRoute"}, jsonHandler(404, ginOpts.ErrorBody.Err404), nil)(c)
			})
		}
		if ginOpts.ErrorBody.Err405 != nil {
			engine.NoMethod(opencensus.HandlerFunc(&config.EndpointConfig{Endpoint: "NoMethod"}, jsonHandler(405, ginOpts.ErrorBody.Err405), nil))
		}
	}

	logPrefix := "[SERVICE: Gin]"
	if err := httpsecure.Register(cfg.ExtraConfig, engine); err != nil && err != httpsecure.ErrNoConfig {
		opt.Logger.Warning(logPrefix+"[HTTPsecure]", err)
	} else if err == nil {
		opt.Logger.Debug(logPrefix + "[HTTPsecure] Successfully loaded module")
	}

	lua.Register(opt.Logger, cfg.ExtraConfig, engine)
	botdetector.Register(cfg, opt.Logger, engine)

	return engine
}

func defaultHandler(c *gin.Context) {
	// BrandingMiddleware rewrites any X-KRAKEND* headers emitted upstream.
	// We set the canonical Hanzo headers directly so there is no leak.
	c.Header(PoweredByHeader, fmt.Sprintf("%s Version %s", BrandName, core.KrakendVersion))
	c.Header(server.CompleteResponseHeaderName, server.HeaderIncompleteResponseValue)
}

func jsonHandler(status int, v interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		defaultHandler(c)
		c.JSON(status, v)
	}
}

type engineFactory struct{}

func (engineFactory) NewEngine(cfg config.ServiceConfig, opt luragin.EngineOptions) *gin.Engine {
	return NewEngine(cfg, opt)
}

type ginOptions struct {
	ErrorBody struct {
		Err404 interface{} `json:"404"`
		Err405 interface{} `json:"405"`
	} `json:"error_body"`
}

// corsPreflightMiddleware handles OPTIONS preflight requests globally.
// Must run before any gateway routing to prevent 405/503 on preflight.
func corsPreflightMiddleware() gin.HandlerFunc {
	// Exact-match origins. Localhost defaults are baked in for dev; extra
	// fully-qualified origins (scheme+host[:port]) may be supplied via the
	// GATEWAY_CORS_ORIGINS env var (comma-separated).
	origins := map[string]bool{
		"http://localhost:3000": true, "http://localhost:3001": true, "http://localhost:3100": true,
		"http://localhost:5173": true, "http://localhost:8080": true, "http://127.0.0.1:3000": true,
	}
	if extra := os.Getenv("GATEWAY_CORS_ORIGINS"); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				origins[o] = true
			}
		}
	}
	// Brand allowlist — the SAME baked-in set the widget security middleware
	// uses (defaultAllowedOrigins). Built once. Every Hanzo/Lux/Zoo/Pars
	// property (and its subdomains) is allowed by hostname suffix-match, so a
	// browser SPA like https://cowork.hanzo.ai gets its AI preflight answered
	// without any per-origin env config. One allowlist source (DRY).
	brandOrigins := widgetAllowedOrigins(defaultAllowedOrigins())
	originAllowed := func(origin string) bool {
		if origins[origin] {
			return true
		}
		return isAllowedOrigin(extractOriginHost(origin), brandOrigins)
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" || !originAllowed(origin) {
			c.Next()
			return
		}
		c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-Id, X-Org-Id, X-Roles, X-User-Email, X-Request-ID, X-Client-ID, X-Requested-With, Accept")
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
