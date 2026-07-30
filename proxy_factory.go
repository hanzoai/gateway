//go:build legacy
// +build legacy

package gateway

import (
	"fmt"

	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	cel "github.com/hanzoai/gateway/v2/internal/plugin/cel"
	jsonschema "github.com/hanzoai/gateway/v2/internal/plugin/jsonschema"
	lua "github.com/hanzoai/gateway/v2/internal/plugin/lua/proxy"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics/gin"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
)

func internalNewProxyFactory(logger logging.Logger, backendFactory proxy.BackendFactory,
	metricCollector *metrics.Metrics) proxy.Factory {

	proxyFactory := proxy.NewDefaultFactory(backendFactory, logger)
	proxyFactory = proxy.NewShadowFactory(proxyFactory)
	proxyFactory = jsonschema.ProxyFactory(logger, proxyFactory)
	proxyFactory = cel.ProxyFactory(logger, proxyFactory)
	proxyFactory = lua.ProxyFactory(logger, proxyFactory)
	proxyFactory = metricCollector.ProxyFactory("pipe", proxyFactory)
	proxyFactory = opencensus.ProxyFactory(proxyFactory)
	return proxyFactory
}

// NewProxyFactory returns a new ProxyFactory wrapping the injected BackendFactory with the default proxy stack and a metrics collector
func NewProxyFactory(logger logging.Logger, backendFactory proxy.BackendFactory, metricCollector *metrics.Metrics) proxy.Factory {
	proxyFactory := internalNewProxyFactory(logger, backendFactory, metricCollector)

	return proxy.FactoryFunc(func(cfg *config.EndpointConfig) (proxy.Proxy, error) {
		logger.Debug(fmt.Sprintf("[ENDPOINT: %s] Building the proxy pipe", cfg.Endpoint))
		return proxyFactory.New(cfg)
	})
}

type proxyFactory struct{}

func (proxyFactory) NewProxyFactory(logger logging.Logger, backendFactory proxy.BackendFactory, metricCollector *metrics.Metrics) proxy.Factory {
	return NewProxyFactory(logger, backendFactory, metricCollector)
}
