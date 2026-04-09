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
	var cfg RoutesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse routes file %s: %w", path, err)
	}
	return LoadRoutes(&cfg)
}

// loadRoutesFromEnv loads routes from KMS path or local file.
// Priority: GATEWAY_ROUTES_KMS_PATH > GATEWAY_ROUTES_FILE > ./routes.yaml
func loadRoutesFromEnv() error {
	// TODO: KMS integration — fetch routes from KMS secret path.
	// if kmsPath := os.Getenv("GATEWAY_ROUTES_KMS_PATH"); kmsPath != "" {
	//     data, err := kms.GetSecret(kmsPath)
	//     ...
	// }

	filePath := os.Getenv("GATEWAY_ROUTES_FILE")
	if filePath == "" {
		filePath = "routes.yaml"
	}
	return LoadRoutesFromFile(filePath)
}

// newProxy creates an httputil.ReverseProxy that preserves the original
// Host header and supports WebSocket upgrade transparently.
func newProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Host = req.URL.Host
	}
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
	return p
}

// apiHanzoAIEndpoints lists the /v1/* path prefixes that route directly
// to cloud-api, bypassing KrakenD JWT middleware.
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
	// Pre-build api.hanzo.ai rewrite proxies.
	cloudAPITarget, _ := url.Parse("http://cloud-api.hanzo.svc.cluster.local:8000")
	apiRewriteProxy := newRewriteProxy(cloudAPITarget, "/v1/", "/api/")
	apiNoRewriteProxy := newRewriteProxy(cloudAPITarget, "/zap", "/api/zap")

	// Allowed CORS origins — covers all Liquidity frontends + localhost dev.
	corsOrigins := map[string]bool{
		// Production
		"https://partner":          true,
		"https://app.partner":      true,
		"https://exchange.partner": true,
		"https://exchange.example.internal": true,
		"https://superadmin.example.internal": true,
		"https://id.example.internal":         true,
		// Testnet
		"https://exchange.test.example.internal":  true,
		"https://superadmin.test.example.internal": true,
		"https://id.test.example.internal":         true,
		// Devnet
		"https://exchange.dev.example.internal":  true,
		"https://superadmin.dev.example.internal": true,
		"https://id.dev.example.internal":         true,
		"https://swap.dev.example.internal":       true,
		"https://api.dev.example.internal":        true,
		// Localhost
		"http://localhost:3000": true,
		"http://localhost:3001": true,
		"http://localhost:3100": true,
		"http://localhost:5173": true,
		"http://localhost:8080": true,
		"http://127.0.0.1:3000": true,
	}

	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]
		path := c.Request.URL.Path

		// CORS for routes.yaml-proxied requests.
		// Only set if not already handled by KrakenD CORS module (avoids duplicate headers).
		origin := c.GetHeader("Origin")
		if origin != "" && corsOrigins[origin] {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-Id, X-Org-Id, X-User-Email, X-Request-ID")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Max-Age", "86400")
			c.Writer.Header().Set("Vary", "Origin")
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
		}

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

		// api.hanzo.ai: route AI endpoints directly to cloud-api.
		if host == "api.hanzo.ai" {
			for _, prefix := range apiHanzoAIEndpoints {
				if strings.HasPrefix(path, prefix) {
					if strings.HasPrefix(path, "/v1/") {
						apiRewriteProxy.ServeHTTP(c.Writer, c.Request)
					} else {
						apiNoRewriteProxy.ServeHTTP(c.Writer, c.Request)
					}
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
	// skips its built-in /__health route (avoids duplicate registration panic).
	// Must modify the raw JSON bytes because lura parses ExtraConfig from JSON,
	// not from the map.
	if cfg.ExtraConfig == nil {
		cfg.ExtraConfig = map[string]interface{}{}
	}
	cfg.ExtraConfig[luragin.Namespace] = map[string]interface{}{
		"disable_health": true,
	}
	engine := luragin.NewEngine(cfg, opt)

	// Load routes from config (KMS or file).
	if err := loadRoutesFromEnv(); err != nil {
		opt.Logger.Warning("[SERVICE: Gateway] Failed to load routes:", err)
		opt.Logger.Warning("[SERVICE: Gateway] No host routing will be available")
	}

	// Register /__health directly. Lura's built-in health is disabled
	// (disable_health: true) to avoid duplicate-route panics, so we must
	// provide the handler that /health (gateway.json) proxies to.
	engine.GET("/__health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

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
	c.Header(core.KrakendHeaderName, core.KrakendHeaderValue)
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
