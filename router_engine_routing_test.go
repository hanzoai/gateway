// Copyright © 2026 Hanzo AI. MIT License.

//go:build legacy
// +build legacy

// gin-driven: this suite drives the LEGACY Lura edge's transports
// (legacy_transports.go), which exist only under this tag. The policies it
// exercises are framework-free values shared with the zip edge, and
// transport_parity_test.go asserts the two edges answer alike.

// Package gateway — AI-endpoint routing regression tests.
//
// These pin the contract that broke prod in the v2.14.x ZAP-relay
// rearchitecture: when the gateway runs as the HTTP edge (the legacy
// legacy `run` path the prod container's CMD drives), api.hanzo.ai's
// /v1/chat/completions and the rest of apiHanzoAIEndpoints MUST be
// proxied straight to cloud over HTTP — NOT 404'd because the only
// live surface was a ZAP relay to backends that don't exist
// (cloud:9090 is cloud's health listener; the base service is absent).
//
// The relay (build_app.go RegisterRelay) is optional: HTTP serving here
// needs no ZAP peer at all.

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// newAPIEdge builds a minimal gin engine wired exactly like the
// production HTTP edge for the cloud passthrough concern: the CORS
// preflight middleware, then hostProxyMiddleware. Auth is intentionally
// left out so the test isolates the ROUTING decision (the auth gate is
// covered by auth_middleware_test.go). The cloud target is pointed
// at a local httptest backend via GATEWAY_CLOUD_API_URL. The engine is
// served from a real httptest.Server (not httptest.NewRecorder) because
// httputil.ReverseProxy requires a CloseNotifier-capable ResponseWriter.
func newAPIEdge(t *testing.T, backend string) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("GATEWAY_CLOUD_API_URL", backend)

	e := gin.New()
	e.Use(corsPreflightMiddleware())
	e.Use(hostProxyMiddleware())
	// Sentinel: if hostProxyMiddleware does NOT abort (i.e. the request
	// fell through unrouted), gin lands here. In prod this is the
	// legacy-engine NoRoute → 404 the v2.14.x relay-only binary returned for
	// every model call.
	e.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "unrouted")
	})
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return srv
}

// TestHostProxy_APIEndpoints_RouteToCloudAPI is the core regression guard.
// Every apiHanzoAIEndpoints prefix on api.hanzo.ai must reach cloud
// (HTTP 200 from the stub), never the NoRoute 404 sentinel.
func TestHostProxy_APIEndpoints_RouteToCloudAPI(t *testing.T) {
	var gotPaths []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	edge := newAPIEdge(t, backend.URL)

	// One representative path per declared prefix, plus the canonical
	// completions route that cowork.hanzo.ai actually calls.
	paths := []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",
		"/v1/models",
		"/v1/embeddings",
		"/v1/images/generations",
		"/v1/audio/speech",
		"/v1/zap",
		"/zap",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, edge.URL+p, strings.NewReader(`{}`))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Host = "api.hanzo.ai"
			resp, err := edge.Client().Do(req)
			if err != nil {
				t.Fatalf("%s: request failed: %v", p, err)
			}
			body := readAll(t, resp)

			if resp.StatusCode == http.StatusNotFound {
				t.Fatalf("%s returned 404 (unrouted) — must proxy to cloud; body=%q", p, body)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: got status %d, want 200 from cloud stub; body=%q", p, resp.StatusCode, body)
			}
			if !strings.Contains(body, `"ok":true`) {
				t.Fatalf("%s: response %q did not come from cloud stub", p, body)
			}
		})
	}

	// The passthrough proxy must forward the path unchanged (cloud
	// speaks /v1/* natively — no /api/ prefix, no rewrite).
	for i, want := range paths {
		if i >= len(gotPaths) {
			t.Fatalf("backend received only %d requests, want %d", len(gotPaths), len(paths))
		}
		if gotPaths[i] != want {
			t.Fatalf("backend saw path %q, want %q (passthrough must not rewrite)", gotPaths[i], want)
		}
	}
}

// TestHostProxy_NonAPIHost_NotProxiedToCloudAPI ensures the cloud
// passthrough is scoped to api.hanzo.ai only — a /v1/* path on some
// other host must not be hijacked to cloud.
func TestHostProxy_NonAPIHost_NotProxiedToCloudAPI(t *testing.T) {
	hit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	edge := newAPIEdge(t, backend.URL)

	req, err := http.NewRequest(http.MethodPost, edge.URL+"/v1/chat/completions", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = "example.com"
	resp, err := edge.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = readAll(t, resp)

	if hit {
		t.Fatal("cloud backend was hit for a non-api.hanzo.ai host")
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-api host /v1/chat/completions: got %d, want 404 (unrouted sentinel)", resp.StatusCode)
	}
}

// readAll drains and closes a response body, returning it as a string.
func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// TestCloudAPIURL_Override pins the env-override + safe-fallback contract
// for the cloud target resolver.
func TestCloudAPIURL_Override(t *testing.T) {
	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("GATEWAY_CLOUD_API_URL", "")
		if got := cloudAPIURL().String(); got != defaultCloudAPIURL {
			t.Fatalf("got %q, want default %q", got, defaultCloudAPIURL)
		}
	})
	t.Run("honors valid override", func(t *testing.T) {
		t.Setenv("GATEWAY_CLOUD_API_URL", "http://cloud-api.example.svc:9000")
		if got := cloudAPIURL().String(); got != "http://cloud-api.example.svc:9000" {
			t.Fatalf("got %q, want override", got)
		}
	})
	t.Run("falls back on malformed override", func(t *testing.T) {
		t.Setenv("GATEWAY_CLOUD_API_URL", "::not a url::")
		if got := cloudAPIURL().String(); got != defaultCloudAPIURL {
			t.Fatalf("got %q, want safe fallback %q", got, defaultCloudAPIURL)
		}
	})
}
