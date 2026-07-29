// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// legacy_engine.go is the LEGACY Lura gin-engine builder for the
// standalone gateway process (cmd/gateway/main_legacy.go). It is the only part
// of the gateway that consumes the upstream `github.com/luraproject/lura` +
// the upstream framework modules; every other file in package gateway — the
// HIP-0110 ZAP relay (build_app.go / gate.go), the trust-boundary mount
// (mount.go), and the pure reverse-proxy routing table (routes.go) — is
// Lura-free.
//
// Gating this file (and its siblings: executor.go, backend_factory.go,
// proxy_factory.go, handler_factory.go, encoding.go, plugin.go, sd.go,
// zap_backend.go, zaphttp_listener.go, base_ha_backend.go,
// base_network_backend.go, rebrand.go) behind the `legacy` build tag keeps the
// upstream Lura graph OUT of the default `go build ./...` and out of the
// shipping `ghcr.io/hanzoai/gateway` image. The legacy path stays compilable
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

	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/gin"
	httpsecure "github.com/hanzoai/gateway/v2/internal/plugin/httpsecure/gin"
	lua "github.com/hanzoai/gateway/v2/internal/plugin/lua/router/gin"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	luragin "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/transport/http/server"
)

// NewEngine creates a new gin engine with middlewares and routing.
func NewEngine(cfg config.ServiceConfig, opt luragin.EngineOptions) *gin.Engine {
	// Force disable_health ON: lura's own /__health would collide with the
	// /healthz registered below (duplicate-route panic), so this gateway always
	// serves its own.
	//
	// MERGE it into whatever the operator configured under the `router`
	// namespace — do NOT replace that map. Replacing it silently discarded every
	// other key an operator set, and `router: {"return_error_msg": true}` is set
	// in BOTH shipping configs (configs/hanzo, configs/lux): the deployed edge
	// answered every upstream failure with a bare status and a zero-length body,
	// so a caller seeing a 500 had nothing to report. The clobber also made the
	// error_body 404/405 re-read at the bottom of this function dead code — it
	// re-read the map it had just overwritten.
	cfg.ExtraConfig = withRouterOption(cfg.ExtraConfig, "disable_health", true)
	engine := luragin.NewEngine(cfg, opt)

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

// withRouterOption returns ec with key=value set inside the lura gin-router
// extra_config namespace (config alias `router`), preserving every other key the
// operator put there. It is the ONE way this package forces a router option, so
// no caller has to know that the namespace is a nested map or that clobbering it
// drops the operator's settings.
//
// It never mutates the caller's nested map: the service config is shared with
// the audit/check commands, so the override is copy-on-write.
func withRouterOption(ec config.ExtraConfig, key string, value interface{}) config.ExtraConfig {
	if ec == nil {
		ec = config.ExtraConfig{}
	}
	merged := map[string]interface{}{}
	if existing, ok := ec[luragin.Namespace].(map[string]interface{}); ok {
		for k, v := range existing {
			merged[k] = v
		}
	}
	merged[key] = value
	ec[luragin.Namespace] = merged
	return ec
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
