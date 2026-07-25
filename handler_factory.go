//go:build legacy
// +build legacy

package gateway

import (
	"fmt"

	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/gin"
	jose "github.com/hanzoai/gateway/v2/internal/plugin/jose"
	ginjose "github.com/hanzoai/gateway/v2/internal/plugin/jose/gin"
	lua "github.com/hanzoai/gateway/v2/internal/plugin/lua/router/gin"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics/gin"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/router/gin"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/transport/http/server"

	"github.com/gin-gonic/gin"
)

// NewHandlerFactory returns a HandlerFactory with a rate-limit and a metrics collector middleware injected
func NewHandlerFactory(logger logging.Logger, metricCollector *metrics.Metrics, rejecter jose.RejecterFactory) router.HandlerFactory {
	handlerFactory := router.CustomErrorEndpointHandler(logger, server.DefaultToHTTPError)
	handlerFactory = ratelimit.NewRateLimiterMw(logger, handlerFactory)
	handlerFactory = lua.HandlerFactory(logger, handlerFactory)
	handlerFactory = ginjose.HandlerFactory(handlerFactory, logger, rejecter)
	handlerFactory = metricCollector.NewHTTPHandlerFactory(handlerFactory)
	handlerFactory = opencensus.New(handlerFactory)
	handlerFactory = botdetector.New(handlerFactory, logger)

	return func(cfg *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logger.Debug(fmt.Sprintf("[ENDPOINT: %s] Building the http handler", cfg.Endpoint))
		return handlerFactory(cfg, p)
	}
}

type handlerFactory struct{}

func (handlerFactory) NewHandlerFactory(l logging.Logger, m *metrics.Metrics, r jose.RejecterFactory) router.HandlerFactory {
	return NewHandlerFactory(l, m, r)
}
