package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	botdetector "github.com/krakend/krakend-botdetector/v2/gin"
	httpsecure "github.com/krakend/krakend-httpsecure/v2/gin"
	lua "github.com/krakend/krakend-lua/v2/router/gin"
	opencensus "github.com/krakend/krakend-opencensus/v2/router/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/core"
	luragin "github.com/luraproject/lura/v2/router/gin"
	"github.com/luraproject/lura/v2/transport/http/server"
)

// pathBackend maps a path prefix to a backend URL.
type pathBackend struct {
	prefix string
	target *url.URL
}

// hostRoute defines routing for a single host with ordered path backends.
type hostRoute struct {
	backends []pathBackend // longest prefix first
}

// hostRoutes maps exact hostnames to their routing config.
// Supports multiple path-based backends per host.
// httputil.ReverseProxy handles WebSocket upgrades natively.
var hostRoutes = map[string][]pathBackend{
	// --- Hanzo core ---
	"hanzo.id":  {{prefix: "/", target: mustURL("http://hanzo-login.hanzo.svc.cluster.local:80")}},
	"hanzo.app": {{prefix: "/", target: mustURL("http://hanzo-app.hanzo.svc.cluster.local:80")}},
	"hanzo.bot": {{prefix: "/", target: mustURL("http://hanzo-bot-site.hanzo.svc.cluster.local:80")}},

	// --- Hanzo Bot ---
	"app.hanzo.bot":    {{prefix: "/", target: mustURL("http://hanzo-playground.hanzo.svc.cluster.local:8080")}},
	"gw.hanzo.bot":     {{prefix: "/", target: mustURL("http://bot-gateway.hanzo.svc.cluster.local:80")}},
	"docs.hanzo.bot":   {{prefix: "/", target: mustURL("http://bot-docs.hanzo.svc.cluster.local:80")}},
	"skills.hanzo.bot": {{prefix: "/", target: mustURL("http://bot-docs.hanzo.svc.cluster.local:80")}},
	"market.hanzo.bot": {{prefix: "/", target: mustURL("http://hanzo-market-site.hanzo.svc.cluster.local:80")}},
	"hub.hanzo.bot": {
		{prefix: "/api", target: mustURL("http://bot-hub.hanzo.svc.cluster.local:3001")},
		{prefix: "/health", target: mustURL("http://bot-hub.hanzo.svc.cluster.local:3001")},
		{prefix: "/", target: mustURL("http://bot-hub.hanzo.svc.cluster.local:80")},
	},

	// --- Hanzo AI services ---
	"analytics.hanzo.ai":  {{prefix: "/", target: mustURL("http://analytics.hanzo.svc.cluster.local:80")}},
	"auto.hanzo.ai":       {{prefix: "/", target: mustURL("http://auto.hanzo.svc.cluster.local:80")}},
	"billing.hanzo.ai":    {{prefix: "/", target: mustURL("http://billing.hanzo.svc.cluster.local:80")}},
	"chat.hanzo.ai":       {{prefix: "/", target: mustURL("http://chat.hanzo.svc.cluster.local:80")}},
	"cloud.hanzo.ai":      {{prefix: "/", target: mustURL("http://cloud.hanzo.svc.cluster.local:80")}},
	"cloud-api.hanzo.ai":  {{prefix: "/", target: mustURL("http://cloud-api.hanzo.svc.cluster.local:8000")}},
	"api.cloud.hanzo.ai":  {{prefix: "/", target: mustURL("http://cloud-api.hanzo.svc.cluster.local:8000")}},
	"commerce.hanzo.ai":       {{prefix: "/", target: mustURL("http://commerce-site.hanzo.svc.cluster.local:80")}},
	"api.commerce.hanzo.ai":   {{prefix: "/", target: mustURL("http://commerce.hanzo.svc.cluster.local:8001")}},
	"admin.commerce.hanzo.ai": {{prefix: "/", target: mustURL("http://commerce-admin.hanzo.svc.cluster.local:80")}},
	"store.commerce.hanzo.ai": {{prefix: "/", target: mustURL("http://commerce-store.hanzo.svc.cluster.local:80")}},
	"console.hanzo.ai":        {{prefix: "/", target: mustURL("http://console.hanzo.svc.cluster.local:80")}},
	"docs.hanzo.ai":           {{prefix: "/", target: mustURL("http://docs-landing.hanzo.svc.cluster.local:3000")}},
	"flow.hanzo.ai":       {{prefix: "/", target: mustURL("http://flow-site.hanzo.svc.cluster.local:80")}},
	"app.flow.hanzo.ai":   {{prefix: "/", target: mustURL("http://flow.hanzo.svc.cluster.local:80")}},
	"iam.hanzo.ai":        {{prefix: "/", target: mustURL("http://iam.hanzo.svc.cluster.local:80")}},
	"kms.hanzo.ai":        {{prefix: "/", target: mustURL("http://kms.hanzo.svc.cluster.local:80")}},
	"mpc.hanzo.ai":        {{prefix: "/", target: mustURL("http://hanzo-mpc.hanzo.svc.cluster.local:8080")}},
	"orm.hanzo.ai":        {{prefix: "/", target: mustURL("http://hanzo-app.hanzo.svc.cluster.local:80")}},
	"pricing.hanzo.ai":    {{prefix: "/", target: mustURL("http://pricing.hanzo.svc.cluster.local:8080")}},
	"registry.hanzo.ai":   {{prefix: "/", target: mustURL("http://registry.hanzo.svc.cluster.local:5000")}},
	"s3.hanzo.ai":         {{prefix: "/", target: mustURL("http://s3.hanzo.svc.cluster.local:9000")}},
	"status.hanzo.ai":     {{prefix: "/", target: mustURL("http://status.hanzo.svc.cluster.local:80")}},
	"studio.hanzo.ai":     {{prefix: "/", target: mustURL("http://studio.hanzo.svc.cluster.local:80")}},
	"visor.hanzo.ai":      {{prefix: "/", target: mustURL("http://visor.hanzo.svc.cluster.local:19000")}},
	"vm.hanzo.ai":         {{prefix: "/", target: mustURL("http://visor.hanzo.svc.cluster.local:19000")}},
	"hanzo.chat":          {{prefix: "/", target: mustURL("http://chat.hanzo.svc.cluster.local:80")}},
	"hanzo.space":         {{prefix: "/", target: mustURL("http://s3.hanzo.svc.cluster.local:9001")}},
	"api.hanzo.space":     {{prefix: "/", target: mustURL("http://s3.hanzo.svc.cluster.local:9000")}},
	"docs.hanzo.space":    {{prefix: "/", target: mustURL("http://s3.hanzo.svc.cluster.local:9001")}},
	"s3.hanzo.space":      {{prefix: "/", target: mustURL("http://s3.hanzo.svc.cluster.local:9000")}},

	// --- Insights (multi-path) ---
	"insights.hanzo.ai": {
		{prefix: "/capture", target: mustURL("http://insights-capture.hanzo.svc.cluster.local:3000")},
		{prefix: "/batch", target: mustURL("http://insights-capture.hanzo.svc.cluster.local:3000")},
		{prefix: "/e", target: mustURL("http://insights-capture.hanzo.svc.cluster.local:3000")},
		{prefix: "/", target: mustURL("http://insights-web.hanzo.svc.cluster.local:80")},
	},

	// --- Platform (multi-path) ---
	"platform.hanzo.ai": {
		{prefix: "/sync", target: mustURL("http://sync.hanzo.svc.cluster.local:4000")},
		{prefix: "/api", target: mustURL("http://platform.hanzo.svc.cluster.local:4000")},
		{prefix: "/socket.io/", target: mustURL("http://platform.hanzo.svc.cluster.local:4000")},
		{prefix: "/v1/", target: mustURL("http://platform.hanzo.svc.cluster.local:4000")},
		{prefix: "/", target: mustURL("http://paas-ui.hanzo.svc.cluster.local:80")},
	},
	"api.platform.hanzo.ai":     {{prefix: "/", target: mustURL("http://platform.hanzo.svc.cluster.local:4000")}},
	"oauth.platform.hanzo.ai":   {{prefix: "/", target: mustURL("http://oauth-proxy.hanzo.svc.cluster.local:80")}},
	"sync.platform.hanzo.ai":    {{prefix: "/", target: mustURL("http://sync.hanzo.svc.cluster.local:4000")}},
	"webhook.platform.hanzo.ai": {{prefix: "/", target: mustURL("http://hanzo-webhook.hanzo.svc.cluster.local:8080")}},

	// --- IAM for partner orgs ---
	"pars.id":       {{prefix: "/", target: mustURL("http://hanzo-login.hanzo.svc.cluster.local:80")}},
	"lux.id":        {{prefix: "/", target: mustURL("http://hanzo-login.hanzo.svc.cluster.local:80")}},
	"id.bootno.de":   {{prefix: "/", target: mustURL("http://iam.hanzo.svc.cluster.local:80")}},
	"id.zoo.network": {{prefix: "/", target: mustURL("http://iam.hanzo.svc.cluster.local:80")}},

	// --- Lux ---
	"api.lux.network":  {{prefix: "/", target: mustURL("http://luxd.lux-mainnet.svc.cluster.local:9650")}},
	"rpc.lux.network":  {{prefix: "/", target: mustURL("http://luxd.lux-mainnet.svc.cluster.local:9650")}},

	// --- ZeroTrust ---
	"zt.hanzo.ai":     {{prefix: "/", target: mustURL("http://hanzo-zt-console.hanzo-zt.svc.cluster.local:80")}},
	"zt-api.hanzo.ai": {{prefix: "/", target: mustURL("http://hanzo-zt-controller.hanzo-zt.svc.cluster.local:443")}},
	"ztc.hanzo.ai":    {{prefix: "/", target: mustURL("http://hanzo-zt-console.hanzo-zt.svc.cluster.local:80")}},

	// --- Zen ---
	"zen.hanzo.ai": {
		{prefix: "/v1", target: mustURL("http://zen-gateway.zen.svc.cluster.local:4100")},
		{prefix: "/health", target: mustURL("http://zen-gateway.zen.svc.cluster.local:4100")},
		{prefix: "/", target: mustURL("http://zen-landing.zen.svc.cluster.local:80")},
	},
	"api.zen.hanzo.ai": {{prefix: "/", target: mustURL("http://zen-gateway.zen.svc.cluster.local:4100")}},

	// --- Hanzo Team ---
	"hanzo.team":     {{prefix: "/", target: mustURL("http://team-nginx.team.svc.cluster.local:80")}},
	"dev.hanzo.team": {{prefix: "/", target: mustURL("http://team-nginx.team.svc.cluster.local:80")}},
}

// hostRedirects maps hostnames that should 301 redirect to a canonical domain.
var hostRedirects = map[string]string{
	"app.hanzo.ai": "https://hanzo.app",
}

// subdomainRoutes maps substring patterns for wildcard-style matching.
// Checked only if no exact host match is found.
var subdomainRoutes = map[string]string{
	"lux-test": "http://luxd.lux-testnet.svc.cluster.local:9640",
	"lux-dev":  "http://luxd.lux-devnet.svc.cluster.local:9650",
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic("bad backend URL: " + raw)
	}
	return u
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
// Used for api.hanzo.ai where /v1/* must map to cloud-api's /api/* routes.
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

// apiHanzoAIEndpoints lists the /v1/* path prefixes that should route directly
// to cloud-api, bypassing KrakenD JWT middleware. Cloud-api handles all auth
// internally (hk-* API keys, JWTs, sk-* provider keys).
// Other paths (billing, auth, analytics) fall through to KrakenD endpoints.
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
// natively via httputil.ReverseProxy. Requests that don't match any host
// fall through to gateway API endpoints.
func hostProxyMiddleware() gin.HandlerFunc {
	// Pre-build proxy instances for exact hosts.
	type compiledRoute struct {
		prefix string
		proxy  *httputil.ReverseProxy
	}
	exactRoutes := make(map[string][]compiledRoute, len(hostRoutes))
	for host, backends := range hostRoutes {
		sorted := make([]pathBackend, len(backends))
		copy(sorted, backends)
		sort.Slice(sorted, func(i, j int) bool {
			return len(sorted[i].prefix) > len(sorted[j].prefix)
		})
		compiled := make([]compiledRoute, len(sorted))
		for i, b := range sorted {
			compiled[i] = compiledRoute{prefix: b.prefix, proxy: newProxy(b.target)}
		}
		exactRoutes[host] = compiled
	}

	// Pre-build proxy instances for subdomain patterns.
	type subProxy struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
	var subProxies []subProxy
	for pattern, target := range subdomainRoutes {
		u, _ := url.Parse(target)
		subProxies = append(subProxies, subProxy{pattern: pattern, proxy: newProxy(u)})
	}

	// Pre-build the api.hanzo.ai rewrite proxy for AI endpoints.
	// These paths bypass KrakenD JWT middleware — cloud-api handles auth.
	cloudAPITarget := mustURL("http://cloud-api.hanzo.svc.cluster.local:8000")
	apiRewriteProxy := newRewriteProxy(cloudAPITarget, "/v1/", "/api/")
	apiNoRewriteProxy := newRewriteProxy(cloudAPITarget, "/zap", "/api/zap")

	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]
		path := c.Request.URL.Path

		// Host redirects (301 permanent).
		if target, ok := hostRedirects[host]; ok {
			c.Redirect(301, target+path)
			c.Abort()
			return
		}

		// api.hanzo.ai: route AI endpoints directly to cloud-api.
		// /v1/* paths are rewritten to /api/* for cloud-api compatibility.
		// Non-AI paths fall through to KrakenD endpoint handlers.
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
			// Non-AI paths fall through to KrakenD endpoints (billing, auth, etc.)
		}

		// Exact host match.
		if routes, ok := exactRoutes[host]; ok {
			for _, r := range routes {
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

// NewEngine creates a new gin engine with some default values and a secure middleware
func NewEngine(cfg config.ServiceConfig, opt luragin.EngineOptions) *gin.Engine {
	engine := luragin.NewEngine(cfg, opt)

	// Auth middleware: validates IAM JWT tokens, checks billing,
	// injects X-Hanzo-Org-Id / X-Hanzo-User-Id / X-Hanzo-User-Email
	// headers into the request before proxying to backends.
	// Runs BEFORE host proxy so downstream services see identity headers.
	engine.Use(NewAuthMiddleware(DefaultAuthConfig()))

	// Widget security: per-IP rate limiting + origin validation for
	// widget keys (hz_*). Prevents abuse of public widget credentials.
	// Runs AFTER auth (so token is already extracted) and BEFORE proxy.
	engine.Use(NewWidgetSecurityMiddleware(DefaultWidgetSecurityConfig()))

	// Host-based transparent proxy: routes all Hanzo domains to their
	// backend services. WebSocket upgrades are handled natively.
	// Unmatched hosts fall through to gateway API endpoints.
	engine.Use(hostProxyMiddleware())

	engine.NoRoute(func(c *gin.Context) {
		// If hostProxyMiddleware already handled it, skip
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
	// ErrorBody sets the json body to return to handlers like NoRoute (404) and NoMethod (405)
	// Example: "404": { "error": "Not Found", "status": 404 }
	ErrorBody struct {
		Err404 interface{} `json:"404"`
		Err405 interface{} `json:"405"`
	} `json:"error_body"`
}
