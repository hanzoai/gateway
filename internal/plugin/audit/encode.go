package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"io"

	"github.com/hanzoai/gateway/v2/internal/hanzolog"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy"
	"github.com/hanzoai/gateway/v2/internal/lura/proxy/plugin"
	router "github.com/hanzoai/gateway/v2/internal/lura/router/gin"
	client "github.com/hanzoai/gateway/v2/internal/lura/transport/http/client/plugin"
	server "github.com/hanzoai/gateway/v2/internal/lura/transport/http/server/plugin"
	bf "github.com/hanzoai/gateway/v2/internal/pkg/bloomfilter/register"
	botdetector "github.com/hanzoai/gateway/v2/internal/plugin/botdetector/krakend"
	httpcache "github.com/hanzoai/gateway/v2/internal/plugin/httpcache"
	httpsecure "github.com/hanzoai/gateway/v2/internal/plugin/httpsecure"
	jose "github.com/hanzoai/gateway/v2/internal/plugin/jose"
	luaproxy "github.com/hanzoai/gateway/v2/internal/plugin/lua/proxy"
	luarouter "github.com/hanzoai/gateway/v2/internal/plugin/lua/router"
	opencensus "github.com/hanzoai/gateway/v2/internal/plugin/opencensus"
	ratelimitProxy "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/proxy"
	ratelimit "github.com/hanzoai/gateway/v2/internal/plugin/ratelimit/router"
)

// Marshal returns the encoded and compressed representation of the Service
func Marshal(s *Service) ([]byte, error) {
	content := applyAlias(s.Clone())

	buff := bytes.Buffer{}
	gzipWriter, _ := gzip.NewWriterLevel(&buff, gzip.BestCompression)
	enc := gob.NewEncoder(gzipWriter)
	if err := enc.Encode(content); err != nil {
		return buff.Bytes(), err
	}
	if err := gzipWriter.Close(); err != nil && err != io.ErrClosedPipe {
		return buff.Bytes(), err
	}
	return buff.Bytes(), nil
}

// Unmarshal decompresses and decodes the received bits into a Service
func Unmarshal(b []byte, s *Service) error {
	zr, err := gzip.NewReader(bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	dec := gob.NewDecoder(zr)
	if err := dec.Decode(s); err != nil {
		return err
	}
	s.normalize()
	return nil
}

var componentAlias = map[string]string{
	server.Namespace:         "a",
	client.Namespace:         "b",
	plugin.Namespace:         "c",
	proxy.Namespace:          "d",
	router.Namespace:         "e",
	bf.Namespace:             "f",
	botdetector.Namespace:    "g",
	opencensus.Namespace:     "h",
	ratelimit.Namespace:      "i",
	ratelimitProxy.Namespace: "j",
	"telemetry/newrelic":     "k",
	"telemetry/ganalytics":   "l",
	"telemetry/instana":      "m",
	jose.ValidatorNamespace:  "n",
	jose.SignerNamespace:     "o",
	"auth/api-keys":          "p",
	httpsecure.Namespace:     "q",
	hanzolog.Namespace:       "r",
	// The gelf and logstash sinks are no longer built into the gateway
	// (logging goes through luxfi/log), but their namespaces stay in this
	// table as literals: it is the audit encoding's stable alphabet, and
	// dropping two entries would renumber nothing but WOULD stop the linter
	// recognising these keys in a config that still carries them.
	"github_com/devopsfaith/krakend-gelf":     "s",
	"github_com/devopsfaith/krakend-logstash": "t",
	"backend/grpc":                     "u",
	"auth/basic":                       "v",
	"server/virtualhost":               "w",
	"server/static-filesystem":         "x",
	"backend/static-filesystem":        "y",
	"backend/http/client":              "z",
	"telemetry/moesif":                 "0",
	"telemetry/opentelemetry":          "1",
	"grpc":                             "2",
	"modifier/response-body-generator": "3",
	"validation/response-json-schema":  "4",
	"websocket":                        "5",
	"modifier/response-headers":        "6",
	luaproxy.ProxyNamespace:            "7",
	luaproxy.BackendNamespace:          "8",
	luarouter.Namespace:                "9",
	httpcache.Namespace:                "10",
	"ai/llm":                           "11",
	"ai/mcp":                           "12",
}

func applyAlias(s Service) Service {
	for k, v := range s.Components {
		if alias, ok := componentAlias[k]; ok {
			s.Components[alias] = v
			delete(s.Components, k)
		}
	}

	for i, a := range s.Agents {
		for k, v := range a.Components {
			if alias, ok := componentAlias[k]; ok {
				s.Agents[i].Components[alias] = v
				delete(s.Agents[i].Components, k)
			}
		}
		for j, b := range a.Backends {
			for k, v := range b.Components {
				if alias, ok := componentAlias[k]; ok {
					s.Agents[i].Backends[j].Components[alias] = v
					delete(s.Agents[i].Backends[j].Components, k)
				}
			}
		}
	}

	for i, e := range s.Endpoints {
		for k, v := range e.Components {
			if alias, ok := componentAlias[k]; ok {
				s.Endpoints[i].Components[alias] = v
				delete(s.Endpoints[i].Components, k)
			}
		}
		for j, b := range e.Backends {
			for k, v := range b.Components {
				if alias, ok := componentAlias[k]; ok {
					s.Endpoints[i].Backends[j].Components[alias] = v
					delete(s.Endpoints[i].Backends[j].Components, k)
				}
			}
		}
	}

	return s
}

func (s *Service) normalize() {
	if s == nil {
		return
	}

	alias := map[string]string{}
	for k, v := range componentAlias {
		alias[v] = k
	}

	if s.Endpoints == nil {
		s.Endpoints = []Endpoint{}
	}
	if s.Agents == nil {
		s.Agents = []Agent{}
	}
	if s.Components == nil {
		s.Components = Component{}
	}

	for k, v := range s.Components {
		if v == nil {
			s.Components[k] = []int{}
		}
		if name, ok := alias[k]; ok {
			s.Components[name] = s.Components[k]
			delete(s.Components, k)
		}
	}

	for _, e := range s.Endpoints {
		if e.Backends == nil {
			e.Backends = []Backend{}
		}
		if e.Components == nil {
			e.Components = Component{}
		}

		for k, v := range e.Components {
			if v == nil {
				e.Components[k] = []int{}
			}
			if name, ok := alias[k]; ok {
				e.Components[name] = e.Components[k]
				delete(e.Components, k)
			}
		}

		for _, b := range e.Backends {
			if b.Components == nil {
				b.Components = Component{}
			}

			for k, v := range b.Components {
				if v == nil {
					b.Components[k] = []int{}
				}
				if name, ok := alias[k]; ok {
					b.Components[name] = b.Components[k]
					delete(b.Components, k)
				}
			}
		}
	}

	for _, a := range s.Agents {
		if a.Backends == nil {
			a.Backends = []Backend{}
		}
		if a.Components == nil {
			a.Components = Component{}
		}

		for k, v := range a.Components {
			if v == nil {
				a.Components[k] = []int{}
			}
			if name, ok := alias[k]; ok {
				a.Components[name] = a.Components[k]
				delete(a.Components, k)
			}
		}

		for _, b := range a.Backends {
			if b.Components == nil {
				b.Components = Component{}
			}

			for k, v := range b.Components {
				if v == nil {
					b.Components[k] = []int{}
				}
				if name, ok := alias[k]; ok {
					b.Components[name] = b.Components[k]
					delete(b.Components, k)
				}
			}
		}
	}
}
