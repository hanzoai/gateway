package gateway

import (
	"encoding/json"
	"net/http/httputil"
	"net/url"
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

// hostProxyTargets maps host patterns to backend URLs.
// The k8s service round-robins across all pods in the deployment.
var hostProxyTargets = map[string]string{
	"lux-test": "http://luxd.lux-testnet.svc.cluster.local:9640",
	"lux-dev":  "http://luxd.lux-devnet.svc.cluster.local:9650",
}

// hostProxyMiddleware intercepts requests for known host patterns and
// transparently proxies them to the correct backend. All paths pass
// through unchanged — no rewriting, no fake prefixes.
// Requests that don't match any pattern fall through to KrakenD.
func hostProxyMiddleware() gin.HandlerFunc {
	proxies := make(map[string]*httputil.ReverseProxy, len(hostProxyTargets))
	for pattern, target := range hostProxyTargets {
		u, _ := url.Parse(target)
		proxies[pattern] = httputil.NewSingleHostReverseProxy(u)
	}

	return func(c *gin.Context) {
		host := strings.Split(c.Request.Host, ":")[0]
		for pattern, proxy := range proxies {
			if strings.Contains(host, pattern) {
				proxy.ServeHTTP(c.Writer, c.Request)
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

	// Host-based transparent proxy: lux-test and lux-dev domains bypass
	// KrakenD and proxy directly to the correct network's luxd service.
	// Default (api.lux.network) falls through to KrakenD endpoints.
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
