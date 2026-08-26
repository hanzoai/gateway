//go:build legacy
// +build legacy

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	asyncamqp "github.com/hanzoai/gateway/v2/internal/plugin/amqp/async"
	cmd "github.com/hanzoai/gateway/v2/internal/plugin/cobra"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/cors/gin" // keep dep, CORS handled by hostProxyMiddleware
	influxdb "github.com/hanzoai/gateway/v2/internal/plugin/influx"
	jose "github.com/hanzoai/gateway/v2/internal/plugin/jose"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics/gin"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/exporter/datadog"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/exporter/influxdb"
	// jaeger, ocagent, and stackdriver exporters dropped — and the OTLP exporter module
	// (OTLP) removed entirely — because each ships telemetry over gRPC
	// (ocagent/stackdriver dial an OpenCensus/gRPC agent; the OTLP exporter module's OTLP
	// collector exporter is gRPC-only), and Hanzo services speak ZAP/HTTP/WS,
	// never gRPC. Legacy-build telemetry rides opencensus (prometheus/datadog/
	// influx/xray/zipkin) + ZAP for inter-service.
	"github.com/hanzoai/gateway/v2/internal/hanzolog"
	"github.com/hanzoai/gateway/v2/internal/lura/async"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/core"
	"github.com/hanzoai/gateway/v2/internal/lura/logging"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	"github.com/hanzoai/gateway/v2/internal/lura/sd/dnssrv"
	serverhttp "github.com/hanzoai/gateway/v2/internal/lura/transport/http/server"
	server "github.com/hanzoai/gateway/v2/internal/lura/transport/http/server/plugin"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/exporter/prometheus"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/exporter/xray"
	_ "github.com/hanzoai/gateway/v2/internal/plugin/opencensus/exporter/zipkin"
)

// NewExecutor returns an executor for the cmd package. The executor initalizes the entire gateway by
// registering the components and composing a RouterFactory wrapping all the middlewares.
func NewExecutor(ctx context.Context) cmd.Executor {
	eb := new(ExecutorBuilder)
	return eb.NewCmdExecutor(ctx)
}

// PluginLoader defines the interface for the collaborator responsible of starting the plugin loaders
// Deprecated: Use PluginLoaderWithContext
type PluginLoader interface {
	Load(folder, pattern string, logger logging.Logger)
}

// PluginLoaderWithContext defines the interface for the collaborator responsible of starting the plugin loaders
type PluginLoaderWithContext interface {
	LoadWithContext(ctx context.Context, folder, pattern string, logger logging.Logger)
}

// SubscriberFactoriesRegister registers all the required subscriber factories from the available service
// discover components and adapters and returns a service register function.
// The service register function will register the service by the given name and port to all the available
// service discover clients
type SubscriberFactoriesRegister interface {
	Register(context.Context, config.ServiceConfig, logging.Logger) func(string, int)
}

// MetricsAndTracesRegister registers the defined observability components and returns a metrics collector,
// if required.
type MetricsAndTracesRegister interface {
	Register(context.Context, config.ServiceConfig, logging.Logger) *metrics.Metrics
}

// EngineFactory returns a gin engine, ready to be passed to the Gateway RouterFactory
type EngineFactory interface {
	NewEngine(config.ServiceConfig, router.EngineOptions) *gin.Engine
}

// ProxyFactory returns a Gateway proxy factory, ready to be passed to the Gateway RouterFactory
type ProxyFactory interface {
	NewProxyFactory(logging.Logger, proxy.BackendFactory, *metrics.Metrics) proxy.Factory
}

// BackendFactory returns a Gateway backend factory, ready to be passed to the Gateway proxy factory
type BackendFactory interface {
	NewBackendFactory(context.Context, logging.Logger, *metrics.Metrics) proxy.BackendFactory
}

// HandlerFactory returns a Gateway router handler factory, ready to be passed to the Gateway RouterFactory
type HandlerFactory interface {
	NewHandlerFactory(logging.Logger, *metrics.Metrics) router.HandlerFactory
}

// LoggerFactory returns a Gateway Logger factory, ready to be passed to the Gateway RouterFactory
type LoggerFactory interface {
	NewLogger(config.ServiceConfig) (logging.Logger, error)
}

// RunServer defines the interface of a function used by the Gateway router to start the service
type RunServer func(context.Context, config.ServiceConfig, http.Handler) error

// RunServerFactory returns a RunServer with several wraps around the injected one
type RunServerFactory interface {
	NewRunServer(logging.Logger, router.RunServerFunc) RunServer
}

// AgentStarter defines a type that starts a set of agents
type AgentStarter interface {
	Start(
		context.Context,
		[]*config.AsyncAgent,
		logging.Logger,
		chan<- string,
		proxy.Factory,
	) func() error
}

// ExecutorBuilder is a composable builder. Every injected property is used by the NewCmdExecutor method.
type ExecutorBuilder struct {
	// PluginLoader is deprecated: Use PluginLoaderWithContext
	PluginLoader                PluginLoader
	PluginLoaderWithContext     PluginLoaderWithContext
	LoggerFactory               LoggerFactory
	SubscriberFactoriesRegister SubscriberFactoriesRegister
	MetricsAndTracesRegister    MetricsAndTracesRegister
	EngineFactory               EngineFactory

	ProxyFactory        ProxyFactory
	BackendFactory      BackendFactory
	HandlerFactory      HandlerFactory
	RunServerFactory    RunServerFactory
	AgentStarterFactory AgentStarter

	Middlewares []gin.HandlerFunc
}

// NewCmdExecutor returns an executor for the cmd package. The executor initializes the entire gateway by
// delegating most of the tasks to the injected collaborators. They register the components and
// compose a RouterFactory wrapping all the middlewares.
// Every nil collaborator is replaced by the default one offered by this package.
func (e *ExecutorBuilder) NewCmdExecutor(ctx context.Context) cmd.Executor {
	e.checkCollaborators()

	return func(cfg config.ServiceConfig) {
		cfg.Normalize()

		logger, err := e.LoggerFactory.NewLogger(cfg)
		if err != nil {
			return
		}

		logger.Info(fmt.Sprintf("Starting Gateway v%s", core.KrakendVersion))

		// The config is this edge's whole statement about credentials, so it is
		// read before anything listens. A statement the binary cannot serve is
		// a boot failure and not a per-request one — see policy.check.
		if err := readPolicy(cfg).check(); err != nil {
			logger.Critical("[SERVICE: Auth]", err.Error())
			os.Exit(1)
		}

		startReporter(ctx, logger, cfg)

		if wd, err := os.Getwd(); err == nil {
			logger.Info("Working directory is", wd)
		}

		dnssrv.SetTTL(cfg.DNSCacheTTL)

		if cfg.Plugin != nil {
			e.PluginLoaderWithContext.LoadWithContext(ctx, cfg.Plugin.Folder, cfg.Plugin.Pattern, logger)
		}

		metricCollector := e.MetricsAndTracesRegister.Register(ctx, cfg, logger)
		if metricsAndTracesCloser, ok := e.MetricsAndTracesRegister.(io.Closer); ok {
			defer metricsAndTracesCloser.Close()
		}

		// Initializes the global cache for the JWK clients if enabled in the config
		if err := jose.SetGlobalCacher(logger, cfg.ExtraConfig); err != nil && err != jose.ErrNoValidatorCfg {
			logger.Error("[SERVICE: JOSE]", err.Error())
		}
		e.SubscriberFactoriesRegister.Register(ctx, cfg, logger)

		bpf := e.BackendFactory.NewBackendFactory(ctx, logger, metricCollector)
		pf := e.ProxyFactory.NewProxyFactory(logger, bpf, metricCollector)

		agentPing := make(chan string, len(cfg.AsyncAgents))

		handlerF := e.HandlerFactory.NewHandlerFactory(logger, metricCollector)

		runServerChain := serverhttp.RunServerWithLoggerFactory(logger)
		runServerChain = router.RunServerFunc(e.RunServerFactory.NewRunServer(logger, runServerChain))

		// Start the inbound ZAP listener (TLS 1.3+PQ) for external clients.
		InitZapListenerFromEnv()
		defer StopZapListener()
		// The ZAP-HTTP listener is booted lazily by the RunServer chain
		// (DefaultRunServerFactory.NewRunServer) once the fully-wrapped
		// handler is available. Just ensure we shut it down on exit.
		defer stopZapHTTPListener()

		// setup the gateway router
		routerFactory := router.NewFactory(router.Config{
			Engine: e.EngineFactory.NewEngine(cfg, router.EngineOptions{
				Logger: logger,
				// Writer is gin's access-log sink. Left nil so gin falls back
				// to its default (stdout) — the same place the service logger
				// writes, and exactly what happened before when no remote log
				// sink was configured (which was always).
				Writer: nil,
				Health: (<-chan string)(agentPing),
			}),
			ProxyFactory:   pf,
			Middlewares:    e.Middlewares,
			Logger:         logger,
			HandlerFactory: handlerF,
			RunServer:      runServerChain,
		})

		// start the engines
		logger.Info("Starting the Gateway instance")

		if len(cfg.AsyncAgents) == 0 {
			routerFactory.NewWithContext(ctx).Run(cfg)
			return
		}

		// start the async agents in the same error group as the router
		g, gctx := errgroup.WithContext(ctx)
		gctx, closeGroupCtx := context.WithCancel(gctx)

		if cfg.SequentialStart {
			waitAgents := e.AgentStarterFactory.Start(gctx, cfg.AsyncAgents, logger, (chan<- string)(agentPing), pf)
			g.Go(waitAgents)
		} else {
			g.Go(func() error {
				return e.AgentStarterFactory.Start(gctx, cfg.AsyncAgents, logger, (chan<- string)(agentPing), pf)()
			})
		}

		g.Go(func() error {
			logger.Info("[SERVICE: Gin] Building the router")
			routerFactory.NewWithContext(ctx).Run(cfg)
			closeGroupCtx()
			return nil
		})

		g.Wait()
	}
}

func (e *ExecutorBuilder) checkCollaborators() {
	if e.PluginLoader == nil {
		e.PluginLoader = new(pluginLoader)
	}
	if e.PluginLoaderWithContext == nil {
		e.PluginLoaderWithContext = new(pluginLoader)
	}
	if e.SubscriberFactoriesRegister == nil {
		e.SubscriberFactoriesRegister = new(registerSubscriberFactories)
	}
	if e.MetricsAndTracesRegister == nil {
		e.MetricsAndTracesRegister = new(MetricsAndTraces)
	}
	if e.EngineFactory == nil {
		e.EngineFactory = new(engineFactory)
	}
	if e.ProxyFactory == nil {
		e.ProxyFactory = new(proxyFactory)
	}
	if e.BackendFactory == nil {
		e.BackendFactory = new(backendFactory)
	}
	if e.HandlerFactory == nil {
		e.HandlerFactory = new(handlerFactory)
	}
	if e.LoggerFactory == nil {
		e.LoggerFactory = new(LoggerBuilder)
	}
	if e.RunServerFactory == nil {
		e.RunServerFactory = new(DefaultRunServerFactory)
	}
	if e.AgentStarterFactory == nil {
		e.AgentStarterFactory = async.AgentStarter([]async.Factory{asyncamqp.StartAgent})
	}
}

// DefaultRunServerFactory creates the default RunServer by wrapping the injected RunServer
// with the plugin loader and the CORS module
type DefaultRunServerFactory struct{}

func (*DefaultRunServerFactory) NewRunServer(l logging.Logger, next router.RunServerFunc) RunServer {
	// CORS is handled by hostProxyMiddleware in router_engine.go.
	// Skip the upstream CORS wrapper to avoid duplicate headers.
	httpRun := RunServer(server.New(
		l,
		server.RunServer(next),
	))
	// Boot the ZAP-HTTP listener once per process with the same fully
	// composed handler that the HTTP listener serves. Additive: HTTP
	// keeps serving regardless of ZAP-HTTP state.
	return func(ctx context.Context, cfg config.ServiceConfig, handler http.Handler) error {
		startZapHTTPListenerOnce(l, handler)
		return httpRun(ctx, cfg, handler)
	}
}

// LoggerBuilder is the default BuilderFactory implementation.
type LoggerBuilder struct{}

// NewLogger sets up the service logger from the configuration.
//
// One backend: luxfi/log, via internal/hanzolog. When the config carries no
// usable telemetry/logging block we fall back to the engine's own basic logger
// at DEBUG on stdout, which is what the previous chain did.
func (LoggerBuilder) NewLogger(cfg config.ServiceConfig) (logging.Logger, error) {
	logger, err := hanzolog.NewLogger(cfg.ExtraConfig)
	if err == nil {
		logger.Debug("[SERVICE: telemetry/logging] structured logging started")
		return logger, nil
	}

	fallback, ferr := logging.NewLogger("DEBUG", os.Stdout, "GATEWAY")
	if ferr != nil {
		return fallback, ferr
	}
	// A malformed block is a configuration error worth surfacing; an absent
	// one is not.
	if !errors.Is(err, hanzolog.ErrWrongConfig) {
		fallback.Error("[SERVICE: telemetry/logging] Unable to create the logger:", err.Error())
	}
	return fallback, nil
}

// MetricsAndTraces is the default implementation of the MetricsAndTracesRegister interface.
type MetricsAndTraces struct {
	shutdownFn func()
}

// Register registers the metrics, influx and opencensus packages as required by the given configuration.
func (m *MetricsAndTraces) Register(ctx context.Context, cfg config.ServiceConfig, l logging.Logger) *metrics.Metrics {
	metricCollector := metrics.New(ctx, cfg.ExtraConfig, l)

	if err := influxdb.New(ctx, cfg.ExtraConfig, metricCollector, l); err != nil {
		if err != influxdb.ErrNoConfig {
			l.Warning("[SERVICE: InfluxDB]", err.Error())
		}
	} else {
		l.Debug("[SERVICE: InfluxDB] Service correctly registered")
	}

	if err := opencensus.Register(ctx, cfg, opencensus.DefaultViews...); err != nil {
		if err != opencensus.ErrNoConfig {
			l.Warning("[SERVICE: OpenCensus]", err.Error())
		}
	} else {
		l.Debug("[SERVICE: OpenCensus] Service correctly registered")
	}

	return metricCollector
}

func (m *MetricsAndTraces) Close() {
	if m.shutdownFn != nil {
		m.shutdownFn()
	}
}

// startReporter is a no-op in the Hanzo fork — no telemetry is sent to upstream.
func startReporter(_ context.Context, _ logging.Logger, _ config.ServiceConfig) {}
