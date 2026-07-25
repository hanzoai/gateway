package audit

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"

	bf "github.com/hanzoai/gateway/v2/internal/pkg/bloomfilter/register"
	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/krakend"
	httpcache "github.com/hanzoai/gateway/v2/internal/plugin/httpcache"
	luaproxy "github.com/hanzoai/gateway/v2/internal/plugin/lua/proxy"
	luarouter "github.com/hanzoai/gateway/v2/internal/plugin/lua/router"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/router"
	rss "github.com/hanzoai/gateway/v2/internal/plugin/rss"
	xml "github.com/hanzoai/gateway/v2/internal/plugin/xml"
	"github.com/hanzoai/gateway/v2/internal/lura/config"
	"github.com/hanzoai/gateway/v2/internal/lura/encoding"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy/plugin"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	client "github.com/hanzoai/gateway/v2/internal/lura/transport/http/client/plugin"
	server "github.com/hanzoai/gateway/v2/internal/lura/transport/http/server/plugin"
)

// Parse creates a Service capturing the details of the received configuration
func Parse(cfg *config.ServiceConfig) Service {
	v1 := 0

	if cfg.Plugin != nil {
		v1 = addBit(v1, ServicePlugin)
	}

	if cfg.SequentialStart {
		v1 = addBit(v1, ServiceSequentialStart)
	}

	if cfg.Debug {
		v1 = addBit(v1, ServiceDebug)
	}

	if cfg.AllowInsecureConnections || (cfg.ClientTLS != nil && cfg.ClientTLS.AllowInsecureConnections) {
		// this global config is deprecates, see below the allow insecure
		// connections inside the client_tls config:
		v1 = addBit(v1, ServiceAllowInsecureConnections)
	}

	if cfg.DisableStrictREST {
		v1 = addBit(v1, ServiceDisableStrictREST)
	}

	if cfg.TLS != nil {
		v1 = addBit(v1, ServiceHasTLS)
		if !cfg.TLS.IsDisabled {
			v1 = addBit(v1, ServiceTLSEnabled)
		}
		if cfg.TLS.EnableMTLS {
			v1 = addBit(v1, ServiceTLSEnableMTLS)
		}
		if cfg.TLS.DisableSystemCaPool {
			v1 = addBit(v1, ServiceTLSDisableSystemCaPool)
		}
		if len(cfg.TLS.CaCerts) > 0 {
			v1 = addBit(v1, ServiceTLSCaCerts)
		}
		if cfg.TLS.PublicKey != "" || cfg.TLS.PrivateKey != "" {
			v1 = addBit(v1, ServiceTLSPrivPubKey)
		}
	}

	if cfg.Echo {
		v1 = addBit(v1, ServiceEcho)
	}

	if cfg.UseH2C {
		v1 = addBit(v1, ServiceUseH2C)
	}

	return Service{
		Details:    []int{v1},
		Agents:     parseAsyncAgents(cfg.AsyncAgents),
		Endpoints:  parseEndpoints(cfg.Endpoints),
		Components: parseComponents(cfg.ExtraConfig),
	}
}

func parseAsyncAgents(as []*config.AsyncAgent) []Agent {
	var agents []Agent

	for _, a := range as {
		agent := Agent{
			Details: []int{
				parseEncoding(a.Encoding),
				a.Consumer.Workers,
				a.Connection.MaxRetries,
				int(a.Consumer.Timeout / time.Millisecond),
			},
			Backends:   parseBackends(a.Backend),
			Components: parseComponents(a.ExtraConfig),
		}

		agents = append(agents, agent)
	}
	return agents
}

const (
	BitEndpointWildcard             int = 0
	BitEndpointQueryStringWildcard  int = 1
	BitEndpointHeaderStringWildcard int = 2
	BitEndpointCatchAll             int = 3
)

func parseEndpoints(es []*config.EndpointConfig) []Endpoint {
	var endpoints []Endpoint

	for _, e := range es {
		wildcards := 0
		if strings.HasSuffix(e.Endpoint, "*") {
			wildcards = 1
		}

		if e.Endpoint == "/__catchall" {
			wildcards = wildcards | (1 << BitEndpointCatchAll)
		}

		for _, s := range e.QueryString {
			if s == "*" {
				wildcards = wildcards | 2
				break
			}
		}
		for _, s := range e.HeadersToPass {
			if s == "*" {
				wildcards = wildcards | 4
				break
			}
		}

		numUnsafeMethods := 0
		for _, b := range e.Backend {
			if b.Method != "HEAD" && b.Method != "GET" {
				numUnsafeMethods++
			} else {
				// TODO: check if this is correct:
				// we consider a gRPC call an unsafe method
				if _, ok := b.ExtraConfig["backend/grpc"]; ok {
					numUnsafeMethods++
				}
			}
		}

		endpoint := Endpoint{
			Details: []int{
				parseEncoding(e.OutputEncoding),
				len(e.QueryString),
				len(e.HeadersToPass),
				int(e.Timeout / time.Millisecond),
				wildcards,
				numUnsafeMethods,
			},
			Backends:   parseBackends(e.Backend),
			Components: parseComponents(e.ExtraConfig),
		}

		endpoints = append(endpoints, endpoint)
	}
	return endpoints
}

func parseEncoding(enc string) int {
	switch enc {
	case encoding.NOOP:
		return addBit(0, EncodingNOOP)
	case encoding.JSON:
		return addBit(0, EncodingJSON)
	case encoding.SAFE_JSON:
		return addBit(0, EncodingSAFEJSON)
	case encoding.STRING:
		return addBit(0, EncodingSTRING)
	case rss.Name:
		return addBit(0, EncodingRSS)
	case xml.Name:
		return addBit(0, EncodingXML)
	default:
		return addBit(0, EncodingOther)
	}
}

func parseBackends(bs []*config.Backend) []Backend {
	var backends []Backend

	for _, b := range bs {
		v1 := parseEncoding(b.Encoding)
		if len(b.AllowList) > 0 {
			v1 = addBit(v1, BackendAllow)
		}
		if len(b.DenyList) > 0 {
			v1 = addBit(v1, BackendDeny)
		}
		if len(b.Mapping) > 0 {
			v1 = addBit(v1, BackendMapping)
		}
		if b.Group != "" {
			v1 = addBit(v1, BackendGroup)
		}
		if b.Target != "" {
			v1 = addBit(v1, BackendTarget)
		}
		if b.IsCollection {
			v1 = addBit(v1, BackendIsCollection)
		}
		backend := Backend{
			Details:    []int{v1},
			Components: parseComponents(b.ExtraConfig),
		}

		backends = append(backends, backend)
	}
	return backends
}

func parseComponents(cfg config.ExtraConfig) Component { // skipcq: GO-R1005
	components := Component{}
	for c, v := range cfg {
		switch c {
		case server.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			if n, ok := cfg["name"].(string); ok {
				components[c] = []int{addBit(0, parseServerPlugin(n))}
				continue
			}

			if ns, ok := cfg["name"].([]interface{}); ok {
				vs := 0
				for _, raw := range ns {
					n, ok := raw.(string)
					if !ok {
						continue
					}
					vs = addBit(vs, parseServerPlugin(n))
				}
				components[c] = []int{vs}
				continue
			}

		case client.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			n, ok := cfg["name"].(string)
			if !ok {
				continue
			}
			components[c] = []int{parseClientPlugin(n)}

		case plugin.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			ns, ok := cfg["name"].([]interface{})
			if !ok {
				continue
			}
			vs := 0
			for _, raw := range ns {
				n, ok := raw.(string)
				if !ok {
					continue
				}
				vs = addBit(vs, parseRespReqPlugin(n))
			}
			components[c] = []int{vs}

		case proxy.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			components[c] = []int{parseProxy(cfg)}

		case router.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			components[c] = []int{parseRouter(cfg)}

		case bf.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			res := make([]int, 3)
			if hn, ok := cfg["hash_name"].(string); ok && hn == "optimal" {
				res[0] = 1
			}
			if ks, ok := cfg["token_keys"].([]interface{}); ok {
				res[1] = len(ks)
			}
			if s, ok := cfg["revoke_server_ping_url"].(string); ok && s != "" {
				res[2] = 1
			}
			components[c] = res

		case botdetector.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			res := make([]int, 4)
			if ks, ok := cfg["allow"].([]interface{}); ok {
				res[0] = len(ks)
			}
			if ks, ok := cfg["deny"].([]interface{}); ok {
				res[1] = len(ks)
			}
			if ks, ok := cfg["patterns"].([]interface{}); ok {
				res[2] = len(ks)
			}
			if s, ok := cfg["cache_size"].(float64); ok {
				res[3] = int(s)
			}
			components[c] = res

		case opencensus.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			exp, ok := cfg["exporters"].(map[string]interface{})
			if !ok {
				continue
			}

			v1 := 0
			if _, ok := exp["logger"]; ok {
				v1 = 1
			}
			if _, ok := exp["zipkin"]; ok {
				v1 += 2
			}
			if _, ok := exp["jaeger"]; ok {
				v1 += 4
			}
			if _, ok := exp["influxdb"]; ok {
				v1 += 8
			}
			if _, ok := exp["prometheus"]; ok {
				v1 += 16
			}
			if _, ok := exp["xray"]; ok {
				v1 += 32
			}
			if _, ok := exp["stackdriver"]; ok {
				v1 += 64
			}
			if _, ok := exp["datadog"]; ok {
				v1 += 128
			}
			if _, ok := exp["ocagent"]; ok {
				v1 += 256
			}

			components[c] = []int{v1}

		case ratelimit.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			v1 := 0
			if vs, ok := cfg["max_rate"].(float64); ok && vs > 0 {
				v1 = 1
			}
			if vs, ok := cfg["client_max_rate"].(float64); ok && vs > 0 {
				v1 += 2
			}
			if vs, ok := cfg["strategy"].(string); ok {
				switch vs {
				case "ip":
					v1 += 4
				case "header":
					v1 += 8
				}
			}

			components[c] = []int{v1}
		case "backend/http/client":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			v1 := 1
			if clientTLS, ok := cfg["client_tls"].(map[string]interface{}); ok {
				var cTLS config.ClientTLS
				err := mapstructure.Decode(clientTLS, &cTLS)
				if err == nil {
					if cTLS.AllowInsecureConnections {
						v1 = addBit(v1, BackendComponentHTTPClientAllowInsecureConnections)
					}
					if len(cTLS.ClientCerts) > 0 {
						// check if we are using client certificates for mTLS against other
						// services
						v1 = addBit(v1, BackendComponentHTTPClientCerts)
					}
				}
			}
			components[c] = []int{v1}
		case "telemetry/moesif":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			eventQueueSize, _ := cfg["event_queue_size"].(int)
			batchSize, _ := cfg["batch_size"].(int)
			timerWakeupSecs, _ := cfg["timer_wake_up_seconds"].(int)
			components[c] = []int{eventQueueSize, batchSize, timerWakeupSecs}
		case "telemetry/opentelemetry":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			metricReportingPeriodFloat, periodOk := cfg["metric_reporting_period"].(float64)
			metricReportingPeriod := int(metricReportingPeriodFloat)
			if !periodOk {
				metricReportingPeriod = -1
			}
			traceSampleRateFloat, rateOk := cfg["trace_sample_rate"].(float64)
			traceSampleRatePercent := int(traceSampleRateFloat * 100.0)
			if !rateOk {
				traceSampleRatePercent = -1
			}
			numOTLPMetrics := 0
			numOTLPTraces := 0
			numPrometheus := 0
			if exporters, ok := cfg["exporters"].(map[string]interface{}); ok {
				if prom, ok := exporters["prometheus"].([]interface{}); ok {
					for _, p := range prom {
						if po, ok := p.(map[string]interface{}); ok {
							if b, ok := po["disable_metrics"].(bool); !ok || !b {
								numPrometheus += 1
							}
						}
					}
				}
				if otlp, ok := exporters["otlp"].([]interface{}); ok {
					for _, o := range otlp {
						if oo, ok := o.(map[string]interface{}); ok {
							if b, ok := oo["disable_metrics"].(bool); !ok || !b {
								numOTLPMetrics += 1
							}
							if b, ok := oo["disable_traces"].(bool); !ok || !b {
								numOTLPTraces += 1
							}
						}
					}
				}
			}
			components[c] = []int{
				metricReportingPeriod,  // warn about too low values in prod
				traceSampleRatePercent, // warn about too high values in prod
				numOTLPMetrics,         // to check if we do not have metrics
				numOTLPTraces,          // to check if we do not have traces
				numPrometheus,          // to check if we do not have metrics
			}
		case "grpc":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			// we need to know if we are using a server and check if we
			// are also using h2c
			server, serverOk := cfg["server"].(map[string]interface{})
			if serverOk {
				numServices := 0
				svcs, ok := server["services"].([]interface{})
				if ok {
					numServices = len(svcs)
				}
				components[c] = []int{
					numServices, // warn about empty lists of services
				}
			}

		case "validation/response-json-schema":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			p := make([]int, 4)
			schemaCfg, schemaCfgOk := cfg["schema"].(map[string]interface{})
			if schemaCfgOk {
				schemaStr, _ := json.Marshal(schemaCfg)
				p[0] = len(schemaStr)
			}
			errorCfg, errorCfgOk := cfg["error"].(map[string]interface{})
			if errorCfgOk {
				customError, customErrorOk := errorCfg["body"].(string)
				if customErrorOk && customError != "" {
					p[1] = 1
				}
				customErrorCode, customErrorCodeOk := errorCfg["status"].(float64)
				if customErrorCodeOk && customErrorCode > 0 {
					p[2] = int(customErrorCode)
				}
				customErrorType, customErrorTypeOk := errorCfg["content_type"].(string)
				if customErrorTypeOk && customErrorType != "" {
					p[3] = 1
				}
			}
			components[c] = p
		case "modifier/response-body":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			p := make([]int, 6)
			modifiers, ok := cfg["modifiers"].([]interface{})
			if ok {
				p[0] = len(modifiers)
				for i := range modifiers {
					var kind string
					for kind = range modifiers[i].(map[string]interface{}) {
					}
					switch kind {
					case "regexp":
						p[1]++
					case "literal":
						p[2]++
					case "upper":
						p[3]++
					case "lower":
						p[4]++
					case "trim":
						p[5]++
					}
				}
			}
			components[c] = p
		case "modifier/response-headers":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			v1 := 0
			if _, ok := cfg["delete"]; ok {
				v1 = addBit(v1, 0)
			}
			if _, ok := cfg["add"]; ok {
				v1 = addBit(v1, 1)
			}
			if _, ok := cfg["rename"]; ok {
				v1 = addBit(v1, 2)
			}
			if _, ok := cfg["replace"]; ok {
				v1 = addBit(v1, 3)
			}

			components[c] = []int{v1}
		case "websocket":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}

			d := make([]int, 11)

			d[0] = 0
			if f, ok := cfg["disable_otel_metrics"].(bool); ok && f {
				d[0] = addBit(d[0], 0)
			}
			if f, ok := cfg["enable_direct_communication"].(bool); ok && f {
				d[0] = addBit(d[0], 1)
			}
			if f, ok := cfg["return_error_details"].(bool); ok && f {
				d[0] = addBit(d[0], 2)
			}
			if f, ok := cfg["connect_event"].(bool); ok && f {
				d[0] = addBit(d[0], 3)
			}
			if f, ok := cfg["disconnect_event"].(bool); ok && f {
				d[0] = addBit(d[0], 4)
			}

			if f, ok := cfg["read_buffer_size"].(float64); ok && f > 0 {
				d[1] = int(f)
			}
			if f, ok := cfg["write_buffer_size"].(float64); ok && f > 0 {
				d[2] = int(f)
			}
			if f, ok := cfg["message_buffer_size"].(float64); ok && f > 0 {
				d[3] = int(f)
			}
			if f, ok := cfg["max_message_size"].(float64); ok && f > 0 {
				d[4] = int(f)
			}
			if f, ok := cfg["max_retries"].(float64); ok && f > 0 {
				d[5] = int(f)
			}

			if f, ok := cfg["write_wait"].(string); ok && f != "" {
				if dur, err := time.ParseDuration(f); err == nil {
					d[6] = int(dur.Milliseconds())
				}
			}
			if f, ok := cfg["pong_wait"].(string); ok && f != "" {
				if dur, err := time.ParseDuration(f); err == nil {
					d[7] = int(dur.Milliseconds())
				}
			}
			if f, ok := cfg["ping_period"].(string); ok && f != "" {
				if dur, err := time.ParseDuration(f); err == nil {
					d[8] = int(dur.Milliseconds())
				}
			}
			if f, ok := cfg["timeout"].(string); ok && f != "" {
				if dur, err := time.ParseDuration(f); err == nil {
					d[9] = int(dur.Milliseconds())
				}
			}

			if f, ok := cfg["subprotocols"].([]interface{}); ok {
				d[10] = len(f)
			}
			components[c] = d
		case luaproxy.ProxyNamespace, luaproxy.BackendNamespace, luarouter.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			f := 0
			if _, ok := cfg["pre"].(string); ok {
				f = addBit(f, 0)
			}
			if _, ok := cfg["post"].(string); ok {
				f = addBit(f, 1)
			}
			components[c] = []int{f}
		case httpcache.Namespace:
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			f := 0
			if e, ok := cfg["shared"].(bool); ok && e {
				f = addBit(f, 0)
			}
			if m, ok := cfg["max_items"].(float64); ok && m > 0 {
				f = addBit(f, 1)
			}
			if m, ok := cfg["max_size"].(float64); ok && m > 0 {
				f = addBit(f, 2)
			}
			components[c] = []int{f}
		case "ai/mcp":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}
			if server, ok := cfg["server_name"].(string); ok && server != "" {
				// This is an endpoint, so we just note its presence
				components[c] = []int{}
				continue
			}

			numServers := 0
			numTools := 0
			servers, serversFound := cfg["servers"].([]interface{})
			if !serversFound {
				continue
			}

			for _, server := range servers {
				server, ok := server.(map[string]interface{})
				if !ok {
					continue
				}
				numServers++

				if tools, ok := server["tools"].([]interface{}); ok {
					numTools += len(tools)
				}
			}
			components[c] = []int{numServers, numTools}
		case "ai/llm":
			cfg, ok := v.(map[string]interface{})
			if !ok {
				components[c] = []int{}
				continue
			}

			for i, pr := range AiProviders {
				p := 0
				customInput := 0
				customOutput := 0
				if prCfg, providerFound := cfg[pr[0]].(map[string]interface{}); providerFound {
					providerVersions := pr[1:]
					vp := 0
					for vi, v := range providerVersions {
						vCfg, versionFound := prCfg[v].(map[string]interface{})
						if !versionFound {
							continue
						}
						p = addBit(p, i)
						vp = addBit(vp, vi)
						if input, ok := vCfg["input_template"].(string); ok && input != "" {
							customInput = 1
						}
						if output, ok := vCfg["output_template"].(string); ok && output != "" {
							customOutput = 1
						}
					}

					components[c] = []int{p, customInput, customOutput, vp}
					break
				}
			}
		default:
			components[c] = []int{}
		}
	}
	return components
}

func parseRouter(cfg config.ExtraConfig) int {
	res := 0
	v, ok := cfg["error_body"].(bool)
	if ok && v {
		res = addBit(res, RouterErrorBody)
	}

	v, ok = cfg["disable_health"].(bool)
	if ok && v {
		res = addBit(res, RouterDisableHealth)
	}

	v, ok = cfg["disable_access_log"].(bool)
	if ok && v {
		res = addBit(res, RouterDisableAccessLog)
	}

	if _, ok := cfg["health_path"]; ok {
		res = addBit(res, RouterHealthPath)
	}

	v, ok = cfg["return_error_msg"].(bool)
	if ok && v {
		res = addBit(res, RouterErrorMsg)
	}

	v, ok = cfg["disable_redirect_trailing_slash"].(bool)
	if ok && v {
		res = addBit(res, RouterDisableRedirectTrailingSlash)
	}

	v, ok = cfg["disable_redirect_fixed_path"].(bool)
	if ok && v {
		res = addBit(res, RouterDisableRedirectFixedPath)
	}

	v, ok = cfg["remove_extra_slash"].(bool)
	if ok && v {
		res = addBit(res, RouterExtraSlash)
	}

	v, ok = cfg["disable_handle_method_not_allowed"].(bool)
	if ok && v {
		res = addBit(res, RouterHandleMethodNotAllowed)
	}

	v, ok = cfg["disable_path_decoding"].(bool)
	if ok && v {
		res = addBit(res, RouterPathDecoding)
	}

	v, ok = cfg["auto_options"].(bool)
	if ok && v {
		res = addBit(res, RouterAutoOptions)
	}

	v, ok = cfg["forwarded_by_client_ip"].(bool)
	if ok && v {
		res = addBit(res, RouterForwardedByClientIp)
	}

	vs, ok := cfg["remote_ip_headers"].([]interface{})
	if ok && len(vs) > 0 {
		res = addBit(res, RouterRemoteIpHeaders)
	}

	vs, ok = cfg["trusted_proxies"].([]interface{})
	if ok && len(vs) > 0 {
		res = addBit(res, RouterTrustedProxies)
	}

	v, ok = cfg["app_engine"].(bool)
	if ok && v {
		res = addBit(res, RouterAppEngine)
	}

	if v, ok := cfg["max_multipart_memory"].(float64); ok && v > 0 {
		res = addBit(res, RouterMaxMultipartMemory)
	}

	vs, ok = cfg["logger_skip_paths"].([]interface{})
	if ok && len(vs) > 0 {
		res = addBit(res, RouterLoggerSkipPaths)
	}

	v, ok = cfg["hide_version_header"].(bool)
	if ok && v {
		res = addBit(res, RouterHideVersionHeader)
	}

	v, ok = cfg["use_h2c"].(bool)
	if ok && v {
		res = addBit(res, RouterUseH2C)
	}

	return res
}

func parseProxy(cfg config.ExtraConfig) int {
	res := 0
	v, ok := cfg["sequential"].(bool)
	if ok && v {
		res = addBit(res, 0)
	}

	if _, ok := cfg["flatmap_filter"]; ok {
		res = addBit(res, 1)
	}

	v, ok = cfg["shadow"].(bool)
	if ok && v {
		res = addBit(res, 2)
	}

	if _, ok := cfg["combiner"]; ok {
		res = addBit(res, 3)
	}

	if _, ok := cfg["static"]; ok {
		res = addBit(res, 4)
	}
	return res
}

func parseServerPlugin(name string) int {
	switch name {
	case "static-filesystem":
		return 1
	case "basic-auth":
		return 2
	case "geoip":
		return 3
	case "redis-ratelimit":
		return 4
	case "url-rewrite":
		return 5
	case "virtualhost":
		return 6
	case "wildcard":
		return 7
	case "ip-filter":
		return 8
	case "jwk-aggregator":
		return 9
	}
	return 0
}

func parseClientPlugin(name string) int {
	switch name {
	case "no-redirect":
		return 1
	case "http-logger":
		return 2
	case "static-filesystem":
		return 3
	case "http-proxy":
		return 4
	}
	return 0
}

func parseRespReqPlugin(name string) int {
	switch name {
	case "response-schema-validator":
		return 1
	case "content-replacer":
		return 2
	}
	return 0
}

func addBit(x, y int) int {
	return x | (1 << y)
}
