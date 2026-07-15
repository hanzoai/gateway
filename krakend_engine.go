// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// krakend_engine.go is the LEGACY Lura/KrakenD gin-engine builder for the
// standalone gateway process (cmd/gateway/main_legacy.go). It is the only part
// of the gateway that consumes the upstream `github.com/luraproject/lura` +
// `github.com/krakend/*` modules; every other file in package gateway — the
// HIP-0110 ZAP relay (build_app.go / gate.go), the trust-boundary mount
// (mount.go), and the pure reverse-proxy routing table (routes.go) — is
// KrakenD-free.
//
// Gating this file (and its siblings: executor.go, backend_factory.go,
// proxy_factory.go, handler_factory.go, encoding.go, plugin.go, sd.go,
// zap_backend.go, zaphttp_listener.go, base_ha_backend.go,
// base_network_backend.go, rebrand.go) behind the `legacy` build tag keeps the
// upstream KrakenD graph OUT of the default `go build ./...` and out of the
// shipping `ghcr.io/hanzoai/gateway` image. The KrakenD path stays compilable
// with `-tags legacy` for the HIP-0110 Phase-A→C rollout safety window; when
// the cloud binary's gateway.Mount registration is the sole edge (Phase C),
// this whole legacy set is deleted.
//
// The pure routing helpers this builder calls — loadRoutesFromEnv,
// corsPreflightMiddleware, hostProxyMiddleware, NewAuthMiddleware,
// NewWidgetSecurityMiddleware — live in the default-build files (routes.go,
// auth_middleware.go, widget_security.go) and are shared with the ZAP relay.
package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	botdetector "github.com/krakend/krakend-botdetector/v2/gin"
	httpsecure "github.com/krakend/krakend-httpsecure/v2/gin"
	lua "github.com/krakend/krakend-lua/v2/router/gin"
	opencensus "github.com/krakend/krakend-opencensus/v2/router/gin"
	"github.com/luraproject/lura/v2/config"
	luragin "github.com/luraproject/lura/v2/router/gin"
	"github.com/luraproject/lura/v2/transport/http/server"
)

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
	// CORS on the error path is gated by the SAME credentialed-origin allowlist
	// as the happy path (newCORSOriginAllower, shared with
	// corsPreflightMiddleware in routes.go).
	engine.Use(gin.CustomRecovery(corsRecoveryHandler(newCORSOriginAllower())))

	// Production response headers: wrap the response writer so the posture
	// (Server = white-label brand by Host, X-Api-Version, HSTS, nosniff) is
	// stamped and every framework-leaking header (X-KRAKEND*, X-Powered-By) is
	// stripped before the response reaches the client. Must run right after
	// recovery so the wrapped writer is in place for every downstream handler.
	engine.Use(ProductionHeadersMiddleware())

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
	// The response posture (Server, X-Api-Version, HSTS, nosniff) and all
	// framework-header stripping are applied by ProductionHeadersMiddleware at
	// write time. Here we only mark the NoRoute / NoMethod response incomplete
	// via the de-branded completion header.
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
