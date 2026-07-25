package audit

import (
	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/krakend"
	cb "github.com/hanzoai/gateway/v2/internal/plugin/circuitbreaker/gobreaker"
	cors "github.com/hanzoai/gateway/v2/internal/plugin/cors"
	gelf "github.com/hanzoai/gateway/v2/internal/plugin/gelf"
	gologging "github.com/hanzoai/gateway/v2/internal/plugin/gologging"
	httpcache "github.com/hanzoai/gateway/v2/internal/plugin/httpcache"
	httpsecure "github.com/hanzoai/gateway/v2/internal/plugin/httpsecure"
	influx "github.com/hanzoai/gateway/v2/internal/plugin/influx"
	jose "github.com/hanzoai/gateway/v2/internal/plugin/jose"
	logstash "github.com/hanzoai/gateway/v2/internal/plugin/logstash"
	metrics "github.com/hanzoai/gateway/v2/internal/plugin/metrics"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
	ratelimitProxy "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/proxy"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/router"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy/plugin"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	client "github.com/hanzoai/gateway/v2/internal/lura/transport/http/client/plugin"
	server "github.com/hanzoai/gateway/v2/internal/lura/transport/http/server/plugin"
)

func hasBit(x, y int) bool {
	return (x>>y)&1 == 1
}

func hasBasicAuth(s *Service) bool {
	// check basic auth in plugin
	if len(s.Components[server.Namespace]) > 0 && hasBit(s.Components[server.Namespace][0], parseServerPlugin("basic-auth")) {
		// old plugin basic auth
		return true
	}
	if len(s.Components["auth/basic"]) > 0 && hasBit(s.Components["auth/basic"][0], 0) {
		// main server config has auth/basic enabled
		return true
	}

	for _, e := range s.Endpoints {
		if len(e.Components["auth/basic"]) > 0 && hasBit(e.Components["auth/basic"][0], 0) {
			return true
		}
	}

	return false
}

func hasTelemetryMissingName(s *Service) bool {
	// TODO: implement this check
	return false
}

func hasDeprecatedServerPlugin(pluginName string) func(s *Service) bool {
	return func(s *Service) bool {
		serverPlugins, ok := s.Components[server.Namespace]
		if !ok {
			return false
		}
		if len(serverPlugins) < 1 {
			return false
		}
		if hasBit(serverPlugins[0], parseServerPlugin(pluginName)) {
			return true
		}
		return false
	}
}

func hasDeprecatedClientPlugin(pluginName string) func(s *Service) bool {
	return func(s *Service) bool {
		compID := parseClientPlugin(pluginName)
		for _, ep := range s.Endpoints {
			comp, ok := ep.Components[client.Namespace]
			if ok && len(comp) > 0 && comp[0] == compID {
				return true
			}
		}
		return false
	}
}

func hasDeprecatedReqRespPlugin(pluginName string) func(s *Service) bool {
	return func(s *Service) bool {
		id := parseRespReqPlugin(pluginName)
		for _, ep := range s.Endpoints {
			comp, ok := ep.Components[plugin.Namespace]
			if ok && hasBit(comp[0], id) {
				return true
			}
			for _, b := range ep.Backends {
				comp, ok := b.Components[plugin.Namespace]
				if ok && hasBit(comp[0], id) {
					return true
				}
			}
		}
		return false
	}
}

func hasApiKeys(s *Service) bool {
	_, ok := s.Components["auth/api-keys"]
	return ok
}

func hasNoJWT(s *Service) bool {
	for _, e := range s.Endpoints {
		if _, ok := e.Components[jose.ValidatorNamespace]; ok {
			return false
		}
	}
	return true
}

func hasInsecureConnections(s *Service) bool {
	return hasBit(s.Details[0], ServiceAllowInsecureConnections)
}

func hasNoTLS(s *Service) bool {
	return !hasBit(s.Details[0], ServiceHasTLS)
}

func hasTLSDisabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceHasTLS) && !hasBit(s.Details[0], ServiceTLSEnabled)
}

func hasNoHTTPSecure(s *Service) bool {
	_, ok := s.Components[httpsecure.Namespace]
	return !ok
}

func hasH2C(s *Service) bool {
	if hasBit(s.Details[0], ServiceUseH2C) {
		return true
	}
	// this is the deprecated way of assing h2c
	v, ok := s.Components[router.Namespace]
	if !ok || len(v) == 0 {
		return false
	}
	return hasBit(v[0], RouterUseH2C)
}

func hasBackendInsecureConnections(s *Service) bool {
	for _, e := range s.Endpoints {
		for _, b := range e.Backends {
			v, ok := b.Components["backend/http/client"]
			if !ok || len(v) == 0 {
				continue
			}
			if hasBit(v[0], BackendComponentHTTPClientAllowInsecureConnections) {
				return true
			}
		}
	}
	return false
}

func hasEndpointWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], BitEndpointWildcard) {
			return true
		}
	}
	return false
}

func hasEndpointCatchAll(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], BitEndpointCatchAll) {
			return true
		}
	}
	return false
}

func hasMultipleUnsafeMethods(s *Service) bool {
	for _, e := range s.Endpoints {
		if e.Details[5] > 1 {
			return true
		}
	}
	return false
}

func hasSequentialProxy(s *Service) bool {
	for _, e := range s.Endpoints {
		p, ok := e.Components[proxy.Namespace]
		if ok && len(p) > 0 && hasBit(p[0], 0) {
			return true
		}
	}
	return false
}

func hasQueryStringWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], 1) {
			return true
		}
	}
	return false
}

func hasHeadersWildcard(s *Service) bool {
	for _, e := range s.Endpoints {
		if hasBit(e.Details[4], 2) {
			return true
		}
	}
	return false
}

func hasNoObfuscatedVersionHeader(s *Service) bool {
	v, ok := s.Components[router.Namespace]
	if !ok || len(v) == 0 {
		return true
	}
	return !hasBit(v[0], RouterHideVersionHeader)
}

func hasNoCORS(s *Service) bool {
	_, ok := s.Components[cors.Namespace]
	return !ok
}

func hasBotdetectorDisabled(s *Service) bool {
	_, ok := s.Components[botdetector.Namespace]
	return !ok
}

func hasNoRatelimit(s *Service) bool {
	_, ok := s.Components[ratelimit.Namespace]
	if ok {
		return false
	}
	for _, e := range s.Endpoints {
		_, ok := e.Components[ratelimit.Namespace]
		if ok {
			return false
		}
		_, ok = e.Components[ratelimitProxy.Namespace]
		if ok {
			return false
		}
		for _, b := range e.Backends {
			_, ok := b.Components[ratelimitProxy.Namespace]
			if ok {
				return false
			}
		}
	}

	_, ok = s.Components["qos/ratelimit/service"]
	if ok {
		return false
	}

	serverPlugins, ok := s.Components[server.Namespace]
	if ok && len(serverPlugins) > 0 {
		pluginsBitset := serverPlugins[0]
		redisRateLimitBit := parseServerPlugin("redis-ratelimit")
		if hasBit(pluginsBitset, redisRateLimitBit) {
			return false
		}
	}

	return true
}

func hasNoCB(s *Service) bool {
	for _, e := range s.Endpoints {
		_, ok := e.Components[cb.Namespace]
		if ok {
			return false
		}
		for _, b := range e.Backends {
			_, ok := b.Components[cb.Namespace]
			if ok {
				return false
			}
		}
	}
	return true
}

func hasTimeoutBiggerThan(d int) func(*Service) bool {
	return func(s *Service) bool {
		for _, e := range s.Endpoints {
			if e.Details[3] > d {
				return true
			}
		}
		return false
	}
}

func hasNoMetrics(s *Service) bool {
	for _, k := range []string{
		opencensus.Namespace,
		metrics.Namespace,
		"telemetry/newrelic",
		"telemetry/ganalytics",
		"telemetry/instana",
	} {
		if _, ok := s.Components[k]; ok {
			return false
		}
	}
	return true
}

func hasSeveralTelemetryComponents(s *Service) bool {
	tot := 0
	for _, k := range []string{
		opencensus.Namespace,
		metrics.Namespace,
		"telemetry/newrelic",
		"telemetry/ganalytics",
		"telemetry/instana",
	} {
		if _, ok := s.Components[k]; ok {
			tot++
		}
	}

	otel, okOTEL := s.Components["telemetry/opentelemetry"]
	if okOTEL && len(otel) >= 5 {
		// OTL enabled metrics + prometheus
		tot += otel[2] + otel[4]
	}
	return tot > 1
}

func hasNoTracing(s *Service) bool {
	_, ok1 := s.Components[opencensus.Namespace]
	_, ok2 := s.Components["telemetry/newrelic"]
	_, ok3 := s.Components["telemetry/instana"]

	otel, okOTEL := s.Components["telemetry/opentelemetry"]
	if okOTEL {
		// in position 3 we have number of enabled OTEL exporters for traces:
		if len(otel) < 4 || otel[3] < 1 {
			okOTEL = false
		}
	}
	return !ok1 && !ok2 && !ok3 && !okOTEL
}

func hasDeprecatedInstana(s *Service) bool {
	_, ok := s.Components["telemetry/instana"]
	return ok
}

func hasDeprecatedGanalytics(s *Service) bool {
	_, ok := s.Components["telemetry/ganalytics"]
	return ok
}

func hasDeprecatedOpenCensus(s *Service) bool {
	_, ok := s.Components[opencensus.Namespace]
	return ok
}

func hasDeprecatedInflux(s *Service) bool {
	_, ok := s.Components[influx.Namespace]
	return ok
}

func hasDeprecatedTLSPrivPubKey(s *Service) bool {
	return hasBit(s.Details[0], ServiceTLSPrivPubKey)
}

func hasNoLogging(s *Service) bool {
	_, ok1 := s.Components[gologging.Namespace]
	_, ok2 := s.Components[gelf.Namespace]
	_, ok3 := s.Components[logstash.Namespace]
	return !ok1 && !ok2 && !ok3
}

func hasRestfulDisabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceDisableStrictREST)
}

func hasDebugEnabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceDebug)
}

func hasEchoEnabled(s *Service) bool {
	return hasBit(s.Details[0], ServiceEcho)
}

func hasEndpointWithoutBackends(s *Service) bool {
	for _, e := range s.Endpoints {
		if len(e.Backends) == 0 {
			return true
		}
	}
	return false
}

func hasASingleBackendPerEndpoint(s *Service) bool {
	for _, e := range s.Endpoints {
		if len(e.Backends) > 1 {
			return false
		}
	}
	return true
}

func hasAllEndpointsAsNoop(s *Service) bool {
	for _, e := range s.Endpoints {
		if !hasBit(e.Details[0], EncodingNOOP) {
			return false
		}
	}
	return true
}

func hasSequentialStart(s *Service) bool {
	return hasBit(s.Details[0], ServiceSequentialStart) && len(s.Agents) >= 10
}

func hasEmptyGRPCServer(s *Service) bool {
	return len(s.Components["grpc"]) > 0 && s.Components["grpc"][0] == 0
}

func hasUnlimitedCache(s *Service) bool {
	for _, e := range s.Endpoints {
		for _, b := range e.Backends {
			cache, ok := b.Components[httpcache.Namespace]
			if !ok {
				continue
			}
			if !hasBit(cache[0], 1) || !hasBit(cache[0], 2) {
				return true
			}
		}
	}
	return false
}
