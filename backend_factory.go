//go:build legacy
// +build legacy

package gateway

import (
	"context"
	"fmt"

	amqp "github.com/hanzoai/gateway/v2/internal/plugin/amqp"
	cel "github.com/hanzoai/gateway/v2/internal/plugin/cel"
	cb "github.com/hanzoai/gateway/v2/internal/plugin/circuitbreaker/gobreaker/proxy"
	httpcache "github.com/hanzoai/gateway/v2/internal/plugin/httpcache"
	lambda "github.com/hanzoai/gateway/v2/internal/plugin/lambda"
	lua "github.com/hanzoai/gateway/v2/internal/plugin/lua/proxy"
	martian "github.com/hanzoai/gateway/v2/internal/plugin/martian"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics/gin"
	oauth2client "github.com/hanzoai/gateway/v2/internal/plugin/oauth2-clientcredentials"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
	pubsub "github.com/hanzoai/gateway/v2/internal/plugin/pubsub"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/proxy"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/lura/transport/http/client"
	httprequestexecutor "github.com/hanzoai/gateway/v2/internal/lura/transport/http/client/plugin"
)

// NewBackendFactory creates a BackendFactory by stacking all the available middlewares:
// - oauth2 client credentials
// - http cache
// - martian
// - pubsub
// - amqp
// - cel
// - lua
// - rate-limit
// - circuit breaker
// - metrics collector
// - opencensus collector
func NewBackendFactory(logger logging.Logger, metricCollector *metrics.Metrics) proxy.BackendFactory {
	return NewBackendFactoryWithContext(context.Background(), logger, metricCollector)
}

func newRequestExecutorFactory(ctx context.Context, logger logging.Logger) func(*config.Backend) client.HTTPRequestExecutor {
	requestExecutorFactory := func(cfg *config.Backend) client.HTTPRequestExecutor {
		clientFactory := client.NewHTTPClient
		if _, ok := cfg.ExtraConfig[oauth2client.Namespace]; ok {
			clientFactory = oauth2client.NewHTTPClient(cfg)
		}

		clientFactory = httpcache.NewHTTPClient(cfg, clientFactory)
		return opencensus.HTTPRequestExecutorFromConfig(clientFactory, cfg)
	}
	// WithContext propagates the application context into client plugins so
	// they observe cancellation and can drain on shutdown (upstream upstream
	// 16a23d2 "Application context is not propagated to client plugins").
	return httprequestexecutor.HTTPRequestExecutorWithContext(ctx, logger, requestExecutorFactory)
}

func internalNewBackendFactory(ctx context.Context, requestExecutorFactory func(*config.Backend) client.HTTPRequestExecutor,
	logger logging.Logger, metricCollector *metrics.Metrics) proxy.BackendFactory {

	backendFactory := martian.NewConfiguredBackendFactory(logger, requestExecutorFactory)
	bf := pubsub.NewBackendFactory(ctx, logger, backendFactory)
	backendFactory = bf.New
	backendFactory = amqp.NewBackendFactory(ctx, logger, backendFactory)
	backendFactory = lambda.BackendFactory(logger, backendFactory)
	backendFactory = cel.BackendFactory(logger, backendFactory)
	backendFactory = lua.BackendFactory(logger, backendFactory)
	backendFactory = ratelimit.BackendFactory(logger, backendFactory)
	backendFactory = cb.BackendFactory(backendFactory, logger)
	backendFactory = metricCollector.BackendFactory("backend", backendFactory)
	backendFactory = opencensus.BackendFactory(backendFactory)
	// ZAP transport: zero-copy binary protocol for internal services
	backendFactory = ZapBackendFactory(logger, backendFactory)
	// base-network: shard-aware routing over base/network-enabled services
	// (ATS, BD, TA, IAM, KMS, AML). See base_network_backend.go.
	backendFactory = BaseNetworkBackendFactory(logger, backendFactory)
	// base_ha: leader-pin + round-robin routing over hanzoai/base-ha
	// clusters (BaseApp CRD). See base_ha_backend.go.
	backendFactory = BaseHABackendFactory(logger, backendFactory)
	return func(remote *config.Backend) proxy.Proxy {
		logger.Debug(fmt.Sprintf("[BACKEND: %s] Building the backend pipe", remote.URLPattern))
		return backendFactory(remote)
	}
}

// NewBackendFactoryWithContext creates a BackendFactory by stacking all the available middlewares and injecting the received context
func NewBackendFactoryWithContext(ctx context.Context, logger logging.Logger, metricCollector *metrics.Metrics) proxy.BackendFactory {
	requestExecutorFactory := newRequestExecutorFactory(ctx, logger)
	return internalNewBackendFactory(ctx, requestExecutorFactory, logger, metricCollector)
}

type backendFactory struct{}

func (backendFactory) NewBackendFactory(ctx context.Context, l logging.Logger, m *metrics.Metrics) proxy.BackendFactory {
	return NewBackendFactoryWithContext(ctx, l, m)
}
