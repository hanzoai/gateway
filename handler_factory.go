//go:build legacy
// +build legacy

package gateway

import (
	"fmt"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/transport/http/server"
	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/gin"
	jose "github.com/hanzoai/gateway/v2/internal/plugin/jose"
	lua "github.com/hanzoai/gateway/v2/internal/plugin/lua/router/gin"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics/gin"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/router/gin"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/router/gin"

	"github.com/gin-gonic/gin"
)

// authPublic is the endpoint key that says a route is reachable without a
// credential — the AI surface (which carries an API key the backend owns),
// the health probes and the public catalogs.
//
// It is a DECLARATION, not a module: the endpoint pipeline runs no JWT
// validator of its own. The one validator is the trust boundary the engine
// installs ahead of routing (authpolicy.go), which verifies the IAM token
// against hanzo.id over TLS, enforces the issuer and the audience allowlist,
// strips what the client claimed and writes what the token proved. This key
// only says whether THIS route needs that to have happened.
//
// The polarity is deliberate: absent means REQUIRED. An endpoint added to the
// config without thinking about auth is gated, not open.
const authPublic = "auth/public"

// public reports whether cfg declares the endpoint reachable without a
// credential. Anything but an explicit `true` is a gated route.
func public(cfg *config.EndpointConfig) bool {
	open, _ := cfg.ExtraConfig[authPublic].(bool)
	return open
}

// requireIdentity refuses a request that reached a gated endpoint carrying no
// verified identity.
//
// This replaces the per-endpoint `auth/validator` module, which ran a SECOND
// JWT validation — a second crypto library, a second JWKS URL (cleartext
// in-cluster, with `disable_jwk_security`), and ALL-of audience semantics
// against the edge's ANY-of — to establish something the edge had already
// established one middleware earlier. Requiring a credential and verifying one
// are different jobs; only the second needs a key, and only one thing should
// do it.
//
// It reads the request's own headers, which is why it cannot disagree with the
// gate: the identity it looks for is the identity the gate wrote, on the same
// request, after deleting whatever the client sent.
func requireIdentity(hf router.HandlerFactory, logger logging.Logger, cfg AuthConfig) router.HandlerFactory {
	return func(ec *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		next := hf(ec, p)
		if public(ec) {
			logger.Debug(fmt.Sprintf("[ENDPOINT: %s] public: no credential required", ec.Endpoint))
			return next
		}
		return func(c *gin.Context) {
			if r := cfg.require(httpHeaders{c.Request.Header}); r != nil {
				c.AbortWithStatusJSON(r.Status, r.Body)
				return
			}
			next(c)
		}
	}
}

// NewHandlerFactory returns a HandlerFactory with a rate-limit and a metrics collector middleware injected
func NewHandlerFactory(logger logging.Logger, metricCollector *metrics.Metrics) router.HandlerFactory {
	handlerFactory := router.CustomErrorEndpointHandler(logger, server.DefaultToHTTPError)
	handlerFactory = ratelimit.NewRateLimiterMw(logger, handlerFactory)
	handlerFactory = lua.HandlerFactory(logger, handlerFactory)
	handlerFactory = requireIdentity(handlerFactory, logger, DefaultAuthConfig())
	handlerFactory = metricCollector.NewHTTPHandlerFactory(handlerFactory)
	handlerFactory = opencensus.New(handlerFactory)
	handlerFactory = botdetector.New(handlerFactory, logger)

	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logger.Debug(fmt.Sprintf("[ENDPOINT: %s] Building the http handler", cfg.Endpoint))
		return handlerFactory(cfg, p)
	}
}

type handlerFactory struct{}

// NewHandlerFactory satisfies the engine's HandlerFactory interface. The
// rejecter it is handed is the token-revocation hook of the endpoint JWT
// validator this gateway no longer runs, so nothing reads it.
func (handlerFactory) NewHandlerFactory(l logging.Logger, m *metrics.Metrics, _ jose.RejecterFactory) router.HandlerFactory {
	return NewHandlerFactory(l, m)
}
