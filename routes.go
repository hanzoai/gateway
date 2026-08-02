// Copyright © 2026 Hanzo AI. MIT License.

// routes.go is the gateway's host/path reverse-proxy routing TABLE — stdlib +
// yaml, with ZERO dependency on the upstream Lura SDK and, now, on any HTTP
// framework. It parses the config, compiles one httputil.ReverseProxy per
// prefix, and holds them behind a hot-reloadable lock. Nothing here answers a
// request.
//
// The table's reader is [hostProxyMiddleware] in legacy_transports.go, the
// standalone edge's transport. It stays gin-side deliberately, and this is the
// one gate in this repo that does NOT have a zip twin:
//
//   - a compiled httputil.ReverseProxy is net/http, and reaching it from a zip
//     handler means the net/http↔fasthttp adaptor, which cannot hijack a
//     connection. WebSocket upgrade and streamed responses — which this proxy
//     serves today — would silently stop working. Carrying it means a NATIVE
//     fasthttp proxy, which is its own reviewable change.
//   - the api-host passthrough below rests on a premise that is FALSE
//     co-resident: it forwards a whole host to the cloud service because cloud
//     is another process. Inside the unified binary that address is the binary
//     itself, and the same rule proxies the process to itself. In cloud-mode the
//     routing source of truth is cloud's own mount table — stated below, in
//     capitals, and true.
//
// The CORS policy that used to live here moved to cors.go, which is what it is;
// this file is the routing table and nothing else.
package gateway

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// RoutesConfig is the YAML structure for gateway routing.
// Loaded from KMS (GATEWAY_ROUTES_KMS_PATH) or local file (GATEWAY_ROUTES_FILE).
type RoutesConfig struct {
	Redirects  map[string]string       `yaml:"redirects" json:"redirects"`
	Routes     map[string][]RouteEntry `yaml:"routes" json:"routes"`
	Subdomains map[string]string       `yaml:"subdomains" json:"subdomains"`
}

// RouteEntry maps a path prefix to a backend URL.
type RouteEntry struct {
	Prefix  string `yaml:"prefix" json:"prefix"`
	Backend string `yaml:"backend" json:"backend"`
	Rewrite string `yaml:"rewrite,omitempty" json:"rewrite,omitempty"` // optional: rewrite prefix
}

// pathBackend maps a path prefix to a backend URL.
type pathBackend struct {
	prefix string
	target *url.URL
}

// compiledRoute is a pre-built proxy for a path prefix.
type compiledRoute struct {
	prefix string
	proxy  *httputil.ReverseProxy
}

// routeTable holds the compiled routing state. Thread-safe for hot-reload.
type routeTable struct {
	mu          sync.RWMutex
	exactRoutes map[string][]compiledRoute
	redirects   map[string]string
	subProxies  []struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
}

var routes = &routeTable{}

// LoadRoutes loads routing config from YAML. Called at startup and on hot-reload.
func LoadRoutes(cfg *RoutesConfig) error {
	exact := make(map[string][]compiledRoute, len(cfg.Routes))

	for host, entries := range cfg.Routes {
		// Sort by longest prefix first.
		sorted := make([]RouteEntry, len(entries))
		copy(sorted, entries)
		sort.Slice(sorted, func(i, j int) bool {
			return len(sorted[i].Prefix) > len(sorted[j].Prefix)
		})

		compiled := make([]compiledRoute, 0, len(sorted))
		for _, e := range sorted {
			u, err := url.Parse(e.Backend)
			if err != nil {
				return fmt.Errorf("bad backend URL %q for %s%s: %w", e.Backend, host, e.Prefix, err)
			}
			var p *httputil.ReverseProxy
			if e.Rewrite != "" {
				p = newRewriteProxy(u, e.Prefix, e.Rewrite)
			} else {
				p = newProxy(u)
			}
			compiled = append(compiled, compiledRoute{prefix: e.Prefix, proxy: p})
		}
		exact[host] = compiled
	}

	type subProxy struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
	var subs []struct {
		pattern string
		proxy   *httputil.ReverseProxy
	}
	for pattern, target := range cfg.Subdomains {
		u, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("bad subdomain backend %q for %s: %w", target, pattern, err)
		}
		subs = append(subs, struct {
			pattern string
			proxy   *httputil.ReverseProxy
		}{pattern: pattern, proxy: newProxy(u)})
	}

	routes.mu.Lock()
	routes.exactRoutes = exact
	routes.redirects = cfg.Redirects
	routes.subProxies = subs
	routes.mu.Unlock()

	return nil
}

// LoadRoutesFromFile loads routes from a YAML file.
func LoadRoutesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read routes file %s: %w", path, err)
	}
	return loadRoutesFromYAML(data)
}

// loadRoutesFromYAML parses a YAML payload and installs the routes table.
// Shared by LoadRoutesFromFile and the KMS code path so both go through one
// validation/parse step.
func loadRoutesFromYAML(data []byte) error {
	var cfg RoutesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse routes yaml: %w", err)
	}
	return LoadRoutes(&cfg)
}

// loadRoutesFromEnv loads routes from KMS path or local file.
// Priority: GATEWAY_ROUTES_KMS_PATH > GATEWAY_ROUTES_FILE > ./routes.yaml
//
// KMS path is delegated to the package-level kmsResolver. When
// GATEWAY_KMS_ENDPOINT is set (plus IAM_CLIENT_ID/SECRET), the HTTP resolver
// is wired automatically. Tests inject a stub via SetKMSResolver.
func loadRoutesFromEnv() error {
	initKMSResolverFromEnv()

	if kmsPath := os.Getenv("GATEWAY_ROUTES_KMS_PATH"); kmsPath != "" {
		data, err := kmsResolver.FetchRoutes(kmsPath)
		if err != nil {
			return fmt.Errorf("failed to fetch routes from KMS path %s: %w", kmsPath, err)
		}
		if err := loadRoutesFromYAML(data); err != nil {
			return fmt.Errorf("kms routes payload invalid: %w", err)
		}
		return nil
	}

	filePath := os.Getenv("GATEWAY_ROUTES_FILE")
	if filePath == "" {
		filePath = "routes.yaml"
	}
	return LoadRoutesFromFile(filePath)
}

// newProxy creates an httputil.ReverseProxy that preserves the original
// Host header and strips backend CORS headers (gateway handles CORS).
func newProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// stripBackendCORS removes CORS headers from backend responses.
// The gateway middleware is the single source of CORS headers.
func stripBackendCORS(resp *http.Response) error {
	resp.Header.Del("Access-Control-Allow-Origin")
	resp.Header.Del("Access-Control-Allow-Methods")
	resp.Header.Del("Access-Control-Allow-Headers")
	resp.Header.Del("Access-Control-Allow-Credentials")
	resp.Header.Del("Access-Control-Max-Age")
	resp.Header.Del("Access-Control-Expose-Headers")
	return nil
}

// newPassthroughProxy creates an httputil.ReverseProxy that forwards the
// request path unchanged to the target host.
func newPassthroughProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// newRewriteProxy creates an httputil.ReverseProxy that rewrites path prefixes.
func newRewriteProxy(target *url.URL, oldPrefix, newPrefix string) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		if strings.HasPrefix(req.URL.Path, oldPrefix) {
			req.URL.Path = newPrefix + req.URL.Path[len(oldPrefix):]
		}
		original(req)
		req.Host = req.URL.Host
	}
	p.ModifyResponse = stripBackendCORS
	return p
}

// defaultCloudAPIURL is the in-cluster cloud (HIP-0106 cloud binary)
// HTTP endpoint that serves /v1/* models traffic natively.
const defaultCloudAPIURL = "http://cloud.hanzo.svc.cluster.local:8000"

// cloudAPIURL resolves the cloud HTTP target. Overridable via
// GATEWAY_CLOUD_API_URL for operators (alternate service DNS) and tests
// (httptest backend). Falls back to defaultCloudAPIURL when unset or
// unparseable so a malformed override can never silently break routing.
func cloudAPIURL() *url.URL {
	raw := strings.TrimSpace(os.Getenv("GATEWAY_CLOUD_API_URL"))
	if raw == "" {
		raw = defaultCloudAPIURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, _ = url.Parse(defaultCloudAPIURL)
	}
	return u
}

// apiCloudHosts is the host whose ENTIRE surface is the unified cloud API.
// ONE API host — api.hanzo.ai (no .cloud.). It resolves to the hanzoai/cloud
// binary (HIP-0106), which owns ALL /v1/* routing — AI inference top-level
// (/v1/chat, /v1/messages, …) plus every per-service control plane (/v1/cloud,
// /v1/iam, /v1/kms, /v1/o11y, …). The gateway is a STATELESS edge: auth +
// ratelimit + meter already ran in the upstream middleware, so it forwards "/*"
// straight to cloud with NO per-route allow-list. ONE routing source of truth =
// cloud's mount table, not a second map here.
var apiCloudHosts = map[string]bool{
	"api.hanzo.ai": true,
	// api.cloud.hanzo.ai is the upstream Host the ingress `console-v1-host` (and
	// `cloud-api-host`) middlewares rewrite console.hanzo.ai/v1/* and
	// cloud-api.hanzo.ai/v1/* to before this gateway. Without it here those hosts
	// fell through to the per-service exactRoutes (which carry /v1/billing,
	// /v1/commerce, … but NOT the visor control plane), so /v1/gpus, /v1/machines,
	// /v1/clusters, /v1/fleet 404'd — breaking the console GPUs + Machines pages for
	// EVERY customer. Treating it as a unified-cloud-API host forwards the WHOLE /v1
	// surface to cloud (which owns visor + all control-plane routing), exactly like
	// api.hanzo.ai. SECURITY unchanged: NewAuthMiddleware runs BEFORE the host
	// passthrough for ALL hosts — it unconditionally strips client identity headers
	// and rewrites X-Org-Id from the validated JWT — so this carries a gateway-
	// sanitized request, never a client-trusted X-Org-Id.
	"api.cloud.hanzo.ai": true,
}
